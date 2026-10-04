//! Which face a text style asks for, and how wide its characters are.
//!
//! A DWG names a font and does not carry it, so every run is drawn with a
//! substitute. The viewer substitutes only from faces it ships, because a
//! system font makes the same drawing measure, wrap and look different on every
//! machine, and because the browser cannot be asked whether it has one.
//!
//! Two pipelines come out of this, and the split is not cosmetic:
//!
//! - A **stroke** style resolves to the bundled stroke font and is drawn as
//!   geometry, so the drawing's lineweight decides the thickness of the letters
//!   exactly as it does in AutoCAD.
//! - A **TrueType** style resolves to one of three bundled faces, chosen by
//!   generic family rather than by name, and the host rasterises it.
//!
//! The bundle is generic on purpose. Drawings name whatever their author had
//! installed, so the tail of font names is endless; what is finite is the
//! handful of shapes CAD text comes in. Specificity lives in the width tables,
//! which are cheap, rather than in the bundle, which is not.

use super::metrics;
use super::stroke_font;

/// Generic shape of a face. The bundle carries one family for each.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Family {
    /// Arimo, metric-compatible with Arial and Helvetica.
    Sans = 0,
    /// Tinos, metric-compatible with Times New Roman.
    Serif = 1,
    /// Cousine, metric-compatible with Courier New.
    Mono = 2,
}

/// One of the bundled outline faces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrueTypeFace {
    pub family: Family,
    pub bold: bool,
    pub italic: bool,
}

/// How a run of text will be drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Face {
    /// Bundled stroke font, drawn as geometry on this side.
    Stroke,
    /// Bundled outline face, rasterised by the host.
    TrueType(TrueTypeFace),
}

impl Default for Face {
    fn default() -> Face {
        Face::TrueType(TrueTypeFace {
            family: Family::Sans,
            bold: false,
            italic: false,
        })
    }
}

/// Number of distinct outline faces in the bundle: three families in four
/// styles. The host keeps a table this size, indexed by [`TrueTypeFace::to_byte`].
pub const FACE_COUNT: u8 = 12;

impl TrueTypeFace {
    /// Pack into the byte a text record carries, which the host turns back
    /// into a face name. Dense over `0..FACE_COUNT`, so the host's side is an
    /// array rather than a match. Stroke runs never reach a record.
    pub fn to_byte(self) -> u8 {
        self.family as u8 * 4 + (self.bold as u8) * 2 + self.italic as u8
    }
}

impl Face {
    /// The byte a text record carries. Stroke runs are drawn here, so if one
    /// ever reaches a record it should still name something drawable.
    pub fn to_byte(self) -> u8 {
        match self {
            Face::Stroke => TrueTypeFace {
                family: Family::Sans,
                bold: false,
                italic: false,
            }
            .to_byte(),
            Face::TrueType(f) => f.to_byte(),
        }
    }
}

/// Resolve the face a text style asks for.
///
/// The font file decides (`arial.ttf`, `romans.shx`, `txt`). A style that
/// names no file but a TrueType family in its `ACAD` extended data is that
/// family, its bold and italic bits and LOGFONT pitch-and-family byte taken
/// from the flags stored beside it.
pub fn resolve_style(style: &crate::cad::TextStyle) -> Face {
    let family = style.font_family.trim();
    if !style.font_file.trim().is_empty() || family.is_empty() {
        return resolve_file(&style.font_file);
    }
    let flags = style.font_flags;
    let stem = family.to_ascii_lowercase();
    Face::TrueType(TrueTypeFace {
        family: family_of(&stem, Some((flags & 0xFF) as u32)),
        bold: flags & 0x0200_0000 != 0,
        italic: flags & 0x0100_0000 != 0,
    })
}

/// Resolve a font **file** name: what a text style stores, and what an MTEXT
/// `\F` override names.
///
/// The extension decides. Stock stroke fonts are stored without one at all
/// ("txt", not "txt.shx"), so testing for ".shx" would miss exactly the common
/// case, and an empty name is AutoCAD's default, which is `txt.shx`.
pub fn resolve_file(named: &str) -> Face {
    let lower = named.trim().to_ascii_lowercase();
    let base = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    let (stem, extension) = match base.rsplit_once('.') {
        Some((s, e)) => (s, Some(e)),
        None => (base, None),
    };
    if !matches!(extension, Some("ttf" | "otf" | "ttc")) {
        return Face::Stroke;
    }
    let (legacy_bold, legacy_italic) = legacy_style(stem);
    Face::TrueType(TrueTypeFace {
        family: family_of(stem, None),
        bold: legacy_bold || bold_from_name(stem),
        italic: legacy_italic || italic_from_name(stem),
    })
}

/// Resolve a font named by an MTEXT `\f` override.
///
/// `\fArial|b0|i1|c0|p34`: `b` and `i` are bold and italic, `c` the code page,
/// and `p` the Windows LOGFONT pitch-and-family byte.
///
/// The name here is a **typeface name**, not a file name: "Arial Narrow", not
/// `arialn.ttf`. So the extension rule that resolves a style does not apply,
/// and the name is an outline face unless it is one of the stock stroke fonts,
/// whose names AutoCAD also lists in the same menu.
pub fn resolve_override(body: &str) -> Face {
    let mut parts = body.split('|');
    let name = parts.next().unwrap_or("").trim();
    let (mut bold, mut italic, mut pitch_family) = (None, None, None);
    for p in parts {
        let Some(key) = p.chars().next() else {
            continue;
        };
        let n = p[key.len_utf8()..].trim().parse::<u32>().ok();
        match key {
            'b' => bold = n.map(|v| v != 0),
            'i' => italic = n.map(|v| v != 0),
            'p' => pitch_family = n,
            _ => {}
        }
    }

    let lower = name.to_ascii_lowercase();
    let stem = lower.rsplit_once('.').map(|(s, _)| s).unwrap_or(&lower);
    if STOCK_STROKE_FONTS.contains(&stem) {
        return Face::Stroke;
    }
    Face::TrueType(TrueTypeFace {
        family: family_of(stem, pitch_family),
        bold: bold.unwrap_or_else(|| bold_from_name(stem)),
        italic: italic.unwrap_or_else(|| italic_from_name(stem)),
    })
}

/// AutoCAD's stock stroke fonts, which appear by bare name in a font menu and
/// so can turn up in an MTEXT override with nothing to mark them as strokes.
const STOCK_STROKE_FONTS: [&str; 26] = [
    "txt", "monotxt", "simplex", "complex", "romans", "romand", "romant", "romanc", "italicc",
    "italict", "scripts", "scriptc", "greeks", "greekc", "gothice", "gothicg", "gothici", "isocp",
    "isocp2", "isocp3", "isoct", "isoct2", "isoct3", "gdt", "ltypeshp", "amgdt",
];

/// Pick a generic family for a face name.
///
/// A name this recognises settles it. The LOGFONT pitch-and-family byte is only
/// consulted for a name that matches nothing, because AutoCAD and BricsCAD both
/// ignore that byte outright: following it over a face we know would make this
/// viewer disagree with the program the drawing was made in. Where the name
/// says nothing it is still the only signal there is, and measured across the
/// corpus the well-known faces carry a real family while the exotic ones carry
/// "don't care".
fn family_of(stem: &str, pitch_family: Option<u32>) -> Family {
    const MONO: [&str; 9] = [
        "courier",
        "cour",
        "cousine",
        "consol",
        "mono",
        "inconsolata",
        "menlo",
        "andale",
        "lucida console",
    ];
    const SERIF: [&str; 13] = [
        "times", "tinos", "georgia", "garamond", "cambria", "caladea", "palatino", "century",
        "book", "minion", "serif", "roman", "slab",
    ];
    const SANS: [&str; 14] = [
        "arial",
        "arimo",
        "helvetica",
        "liberation sans",
        "calibri",
        "carlito",
        "verdana",
        "tahoma",
        "segoe",
        "roboto",
        "lato",
        "futura",
        "univers",
        "frutiger",
    ];
    // Most specific first: "Courier New" must not be read as a serif for
    // containing "roman"-adjacent words, and a "sans" in the name beats the
    // "serif" inside it.
    if MONO.iter().any(|m| stem.contains(m)) {
        return Family::Mono;
    }
    if stem.contains("sans") || SANS.iter().any(|s| stem.contains(s)) {
        return Family::Sans;
    }
    if SERIF.iter().any(|s| stem.contains(s)) {
        return Family::Serif;
    }

    if let Some(pf) = pitch_family {
        match pf & 0xF0 {
            0x10 => return Family::Serif, // FF_ROMAN
            0x20 => return Family::Sans,  // FF_SWISS
            0x30 => return Family::Mono,  // FF_MODERN
            _ => {}
        }
        // FIXED_PITCH, with the family left unsaid.
        if pf & 0x03 == 1 {
            return Family::Mono;
        }
    }

    Family::Sans
}

/// Style words any name might spell out.
fn bold_from_name(stem: &str) -> bool {
    stem.contains("bold") || stem.contains("black") || stem.contains("heavy")
}

fn italic_from_name(stem: &str) -> bool {
    stem.contains("italic") || stem.contains("oblique")
}

/// Style encoded in a legacy 8.3 file stem: `arialbd`, `ariali`, `timesbi`,
/// `ariblk`.
///
/// Only ever applied to a file name. A typeface name cannot be read this way
/// ("Kanji" and "Bodoni" would both come out italic), and it never needs to be,
/// since an MTEXT override carries explicit bold and italic flags.
fn legacy_style(stem: &str) -> (bool, bool) {
    if !(stem.len() <= 8 && stem.chars().all(|c| c.is_ascii_alphanumeric())) {
        return (false, false);
    }
    match () {
        _ if stem.ends_with("bi") => (true, true),
        _ if stem.ends_with("blk") => (true, false),
        _ if stem.ends_with("bd") => (true, false),
        _ if stem.ends_with('i') => (false, true),
        _ => (false, false),
    }
}

/// Advance widths of the face a run is drawn with.
///
/// Everything here is in **cap heights**, not ems, because a DWG text height is
/// a cap height. A run at height `h` multiplies these by `h` and nothing else.
/// For the stroke font that is the native unit; for an outline face the cap
/// ratio is divided out here, once, rather than at every use.
#[derive(Clone, Copy)]
pub struct Metrics {
    face: Face,
    /// Dense advances in em units, `metrics::FIRST` up.
    dense: &'static [u16],
    /// Advances past the dense range, sorted by codepoint.
    sparse: &'static [(u32, u16)],
    /// Cap height as a fraction of em.
    cap_ratio: f32,
}

impl Metrics {
    pub fn for_face(face: Face) -> Metrics {
        let (dense, sparse, cap_ratio) = match face {
            // Unused: the stroke font answers from its own tables below.
            Face::Stroke => (
                &metrics::SANS[..],
                &metrics::SANS_SPARSE[..],
                metrics::SANS_CAP,
            ),
            Face::TrueType(f) => table_for(f),
        };
        Metrics {
            face,
            dense,
            sparse,
            cap_ratio,
        }
    }

    pub fn face(&self) -> Face {
        self.face
    }

    /// Cap height as a fraction of em. Only an outline face has one; the
    /// stroke font is defined in cap heights already.
    pub fn cap_ratio(&self) -> f64 {
        self.cap_ratio as f64
    }

    /// Advance of one character, in cap heights.
    pub fn advance(&self, c: char) -> f64 {
        if self.face == Face::Stroke {
            return stroke_font::newstroke().advance(c) as f64;
        }
        let cp = c as u32;
        let em = if (metrics::FIRST..=metrics::LAST).contains(&cp) {
            match self.dense[(cp - metrics::FIRST) as usize] {
                0 => None,
                v => Some(v),
            }
        } else {
            self.sparse
                .binary_search_by_key(&cp, |(k, _)| *k)
                .ok()
                .map(|i| self.sparse[i].1)
        };
        match em {
            Some(v) => v as f64 / metrics::SCALE as f64 / self.cap_ratio as f64,
            // Outside every table. The CJK, Hangul and fullwidth blocks are one
            // em square; anything else takes a middling Latin advance.
            None if cp >= 0x2E80 => 1.0 / self.cap_ratio as f64,
            None => 0.5 / self.cap_ratio as f64,
        }
    }

    /// Width of a string, in cap heights.
    pub fn measure(&self, s: &str) -> f64 {
        s.chars().map(|c| self.advance(c)).sum()
    }
}

fn table_for(f: TrueTypeFace) -> (&'static [u16], &'static [(u32, u16)], f32) {
    use Family::*;
    match (f.family, f.bold, f.italic) {
        (Sans, false, false) => (&metrics::SANS, &metrics::SANS_SPARSE, metrics::SANS_CAP),
        (Sans, true, false) => (
            &metrics::SANS_BOLD,
            &metrics::SANS_BOLD_SPARSE,
            metrics::SANS_BOLD_CAP,
        ),
        (Sans, false, true) => (
            &metrics::SANS_ITALIC,
            &metrics::SANS_ITALIC_SPARSE,
            metrics::SANS_ITALIC_CAP,
        ),
        (Sans, true, true) => (
            &metrics::SANS_BOLD_ITALIC,
            &metrics::SANS_BOLD_ITALIC_SPARSE,
            metrics::SANS_BOLD_ITALIC_CAP,
        ),
        (Serif, false, false) => (&metrics::SERIF, &metrics::SERIF_SPARSE, metrics::SERIF_CAP),
        (Serif, true, false) => (
            &metrics::SERIF_BOLD,
            &metrics::SERIF_BOLD_SPARSE,
            metrics::SERIF_BOLD_CAP,
        ),
        (Serif, false, true) => (
            &metrics::SERIF_ITALIC,
            &metrics::SERIF_ITALIC_SPARSE,
            metrics::SERIF_ITALIC_CAP,
        ),
        (Serif, true, true) => (
            &metrics::SERIF_BOLD_ITALIC,
            &metrics::SERIF_BOLD_ITALIC_SPARSE,
            metrics::SERIF_BOLD_ITALIC_CAP,
        ),
        (Mono, false, false) => (&metrics::MONO, &metrics::MONO_SPARSE, metrics::MONO_CAP),
        (Mono, true, false) => (
            &metrics::MONO_BOLD,
            &metrics::MONO_BOLD_SPARSE,
            metrics::MONO_BOLD_CAP,
        ),
        (Mono, false, true) => (
            &metrics::MONO_ITALIC,
            &metrics::MONO_ITALIC_SPARSE,
            metrics::MONO_ITALIC_CAP,
        ),
        (Mono, true, true) => (
            &metrics::MONO_BOLD_ITALIC,
            &metrics::MONO_BOLD_ITALIC_SPARSE,
            metrics::MONO_BOLD_ITALIC_CAP,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tt(face: Face) -> TrueTypeFace {
        match face {
            Face::TrueType(f) => f,
            Face::Stroke => panic!("expected a TrueType face, got stroke"),
        }
    }

    /// The case the corpus is full of: a stock stroke font, stored with no
    /// extension at all. Testing for ".shx" would miss every one of these.
    #[test]
    fn stock_stroke_fonts_have_no_extension() {
        for name in [
            "txt",
            "simplex",
            "romans",
            "isocp",
            "monotxt",
            "ltypeshp.shx",
        ] {
            assert_eq!(resolve_file(name), Face::Stroke, "{name}");
        }
    }

    #[test]
    fn an_unnamed_font_is_the_autocad_default() {
        // AutoCAD falls back to txt.shx, which is a stroke font.
        assert_eq!(resolve_file(""), Face::Stroke);
    }

    fn style(font_file: &str, family: &str, flags: i64) -> crate::cad::TextStyle {
        crate::cad::TextStyle {
            font_file: font_file.to_string(),
            font_family: family.to_string(),
            font_flags: flags,
            ..Default::default()
        }
    }

    /// AutoCAD writes a TrueType style as its file and, in extended data,
    /// its family name: the family has no extension and must not turn the
    /// style into a stroke font.
    #[test]
    fn a_style_with_a_truetype_file_and_its_family_is_truetype() {
        let f = tt(resolve_style(&style("arial.ttf", "Arial", 34)));
        assert_eq!((f.family, f.bold, f.italic), (Family::Sans, false, false));
        assert_eq!(resolve_style(&style("romans.shx", "", 0)), Face::Stroke);
        assert_eq!(resolve_style(&style("", "", 0)), Face::Stroke);
    }

    /// A style naming no file is the family its extended data names, with
    /// the bold and italic bits stored beside it.
    #[test]
    fn a_style_with_only_a_family_is_that_family() {
        let f = tt(resolve_style(&style(
            "",
            "Times New Roman",
            0x0100_0000 | 0x12,
        )));
        assert_eq!((f.family, f.bold, f.italic), (Family::Serif, false, true));
        let f = tt(resolve_style(&style("", "SimSun", 0x0200_0000 | 0x31)));
        assert_eq!((f.family, f.bold, f.italic), (Family::Mono, true, false));
    }

    #[test]
    fn outline_extensions_are_truetype() {
        for name in ["arial.ttf", "Tahoma.TTF", "SomeFace.otf", "a.ttc"] {
            assert!(matches!(resolve_file(name), Face::TrueType(_)), "{name}");
        }
    }

    #[test]
    fn families_come_from_the_name() {
        assert_eq!(tt(resolve_file("arial.ttf")).family, Family::Sans);
        assert_eq!(tt(resolve_file("times.ttf")).family, Family::Serif);
        assert_eq!(tt(resolve_file("cour.ttf")).family, Family::Mono);
        assert_eq!(tt(resolve_file("consola.ttf")).family, Family::Mono);
        // A face nobody has heard of falls to the default rather than failing.
        assert_eq!(
            tt(resolve_file("EncodeSansCondensed-Regular.ttf")).family,
            Family::Sans
        );
    }

    /// A path is stripped before the name is read, since drawings sometimes
    /// carry one.
    #[test]
    fn a_path_is_stripped() {
        let f = tt(resolve_file(r"C:\Windows\Fonts\timesbd.ttf"));
        assert_eq!(f.family, Family::Serif);
        assert!(f.bold);
    }

    #[test]
    fn legacy_names_carry_their_style() {
        let bd = tt(resolve_file("arialbd.ttf"));
        assert!(bd.bold && !bd.italic);
        let bi = tt(resolve_file("arialbi.ttf"));
        assert!(bi.bold && bi.italic);
        let blk = tt(resolve_file("ariblk.ttf"));
        assert!(blk.bold);
        let plain = tt(resolve_file("arial.ttf"));
        assert!(!plain.bold && !plain.italic);
    }

    /// The trailing-"i" rule reads a legacy 8.3 file stem. A typeface name that
    /// happens to end in one must not come out italic, which is why the rule is
    /// never applied to an MTEXT override.
    #[test]
    fn a_typeface_name_ending_in_i_is_not_italic() {
        for name in ["Kanji", "Bodoni", "Rockwell Multi"] {
            let f = tt(resolve_override(name));
            assert!(!f.italic, "{name} came out italic");
        }
        assert_eq!(legacy_style("ariali"), (false, true));
        assert_eq!(legacy_style("timesbi"), (true, true));
        assert_eq!(legacy_style("arialbd"), (true, false));
        assert_eq!(legacy_style("ariblk"), (true, false));
        assert_eq!(legacy_style("arial"), (false, false));
        // Too long, or punctuated, so not an 8.3 stem at all.
        assert_eq!(legacy_style("encodesanscondensed-regular"), (false, false));
    }

    /// `\fArial|b0|i1|c0|p34`: p34 is 0x22, variable pitch, family Swiss.
    #[test]
    fn override_reads_the_logfont_fields() {
        let f = tt(resolve_override("Arial|b0|i1|c0|p34"));
        assert_eq!(f.family, Family::Sans);
        assert!(!f.bold);
        assert!(f.italic, "i1 means italic");
    }

    #[test]
    fn override_bold_beats_the_name() {
        // The name says nothing, the flag says bold.
        let f = tt(resolve_override("Arial|b1|i0|c0|p34"));
        assert!(f.bold);
        // And the flag can also say a bold-looking name is not bold.
        let f = tt(resolve_override("arialbd|b0|i0|c0|p34"));
        assert!(!f.bold, "an explicit b0 should override the name");
    }

    /// The name outranks the LOGFONT byte, because AutoCAD and BricsCAD ignore
    /// that byte entirely. Following it over a name we recognise would make
    /// this viewer disagree with the program the drawing came from.
    #[test]
    fn the_name_outranks_the_logfont_byte() {
        // 0x10 is FF_ROMAN, but the name is a sans we know.
        let f = tt(resolve_override("Arial|b0|i0|c0|p16"));
        assert_eq!(f.family, Family::Sans);
        let f = tt(resolve_override("Courier New|b0|i0|c0|p16"));
        assert_eq!(f.family, Family::Mono);
    }

    /// Where the name says nothing, the byte is the only signal there is.
    #[test]
    fn logfont_family_breaks_a_tie() {
        // FF_ROMAN on a name no rule recognises.
        let f = tt(resolve_override("Zapfino Whatever|b0|i0|c0|p16"));
        assert_eq!(f.family, Family::Serif);
        // FF_MODERN likewise.
        let f = tt(resolve_override("Zapfino Whatever|b0|i0|c0|p48"));
        assert_eq!(f.family, Family::Mono);
        // FF_DONTCARE leaves the default.
        let f = tt(resolve_override("Zapfino Whatever|b0|i0|c0|p0"));
        assert_eq!(f.family, Family::Sans);
    }

    /// FIXED_PITCH with no family stated still means monospace.
    #[test]
    fn fixed_pitch_alone_means_monospace() {
        let f = tt(resolve_override("Whatever|b0|i0|c0|p1"));
        assert_eq!(f.family, Family::Mono);
    }

    /// A `\f` names a typeface, not a file, so the extension rule cannot apply
    /// to it. Only the stock stroke font names resolve to strokes.
    #[test]
    fn override_names_a_typeface_not_a_file() {
        assert_eq!(resolve_override("txt|b0|i0|c0|p0"), Face::Stroke);
        assert_eq!(resolve_override("romans"), Face::Stroke);
        // No extension, but plainly an outline face.
        assert!(matches!(
            resolve_override("Arial Narrow"),
            Face::TrueType(_)
        ));
        assert!(matches!(
            resolve_override("Arial Nova|b0|i0|c0|p34"),
            Face::TrueType(_)
        ));
    }

    #[test]
    fn override_survives_a_bare_name() {
        let f = tt(resolve_override("Arial Narrow"));
        assert_eq!(f.family, Family::Sans);
    }

    #[test]
    fn face_byte_round_trips_every_combination() {
        let mut seen = std::collections::BTreeSet::new();
        for family in [Family::Sans, Family::Serif, Family::Mono] {
            for bold in [false, true] {
                for italic in [false, true] {
                    let b = TrueTypeFace {
                        family,
                        bold,
                        italic,
                    }
                    .to_byte();
                    assert!(seen.insert(b), "byte {b} used twice");
                    assert!(b < FACE_COUNT, "byte {b} out of the host's table");
                }
            }
        }
        // Dense, so the host's side is an array of exactly this length.
        assert_eq!(seen.len(), FACE_COUNT as usize);
        assert_eq!(*seen.last().unwrap(), FACE_COUNT - 1);
    }

    /// Cap heights, because a DWG text height is one. A capital set at height
    /// 1.0 should measure about 1.0 tall, so an advance lands near it.
    #[test]
    fn advances_are_in_cap_heights() {
        let m = Metrics::for_face(Face::default());
        // Arimo's "H" is 0.722 em wide with a cap height of 0.688 em.
        let h = m.advance('H');
        assert!((h - 0.722 / 0.688).abs() < 0.01, "H advanced {h}");
        // "i" is much narrower than "m" in a proportional face.
        assert!(m.advance('i') < m.advance('m'));
    }

    #[test]
    fn monospace_advances_are_uniform() {
        let m = Metrics::for_face(Face::TrueType(TrueTypeFace {
            family: Family::Mono,
            bold: false,
            italic: false,
        }));
        let w = m.advance('i');
        for c in "iWM.l".chars() {
            assert!((m.advance(c) - w).abs() < 1e-6, "{c:?} broke the pitch");
        }
    }

    #[test]
    fn bold_is_wider_than_regular() {
        let regular = Metrics::for_face(Face::default());
        let bold = Metrics::for_face(Face::TrueType(TrueTypeFace {
            family: Family::Sans,
            bold: true,
            italic: false,
        }));
        let (a, b) = (
            regular.measure("PLAN DE MASSE"),
            bold.measure("PLAN DE MASSE"),
        );
        assert!(b > a, "bold {b} should exceed regular {a}");
    }

    /// The stroke font answers from its own data, in its own native unit.
    #[test]
    fn stroke_metrics_come_from_the_stroke_font() {
        let m = Metrics::for_face(Face::Stroke);
        assert_eq!(m.advance('A'), stroke_font::newstroke().advance('A') as f64);
        assert!(m.advance('I') < m.advance('W'));
    }

    /// The sparse tail exists for characters past Latin Extended-A that
    /// drawings really use. The euro is the test case that must resolve.
    #[test]
    fn sparse_characters_resolve() {
        let m = Metrics::for_face(Face::default());
        let fallback = 0.5 / metrics::SANS_CAP as f64;
        assert!(
            (m.advance('€') - fallback).abs() > 1e-9,
            "euro should come from the sparse table, not the fallback"
        );
        assert!(m.advance('€') > 0.0);
    }

    /// Nothing may panic or return a nonsense width, whatever it is handed.
    #[test]
    fn every_character_has_a_finite_width() {
        for face in [
            Face::Stroke,
            Face::default(),
            Face::TrueType(TrueTypeFace {
                family: Family::Mono,
                bold: true,
                italic: true,
            }),
        ] {
            let m = Metrics::for_face(face);
            for cp in (0u32..0x3000).chain([0x1F600, 0x10FFFF]) {
                let Some(c) = char::from_u32(cp) else {
                    continue;
                };
                let a = m.advance(c);
                assert!((0.0..10.0).contains(&a), "U+{cp:04X} advanced {a}");
            }
        }
    }
}
