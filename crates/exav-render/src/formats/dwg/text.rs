//! Text placement records.
//!
//! An outline glyph is rasterised by the host, so for those this side stops at
//! placement: anchor point, height, rotation, slant, the alignment codes and
//! which bundled face to use. The renderer finishes the layout. A stroke glyph
//! never gets this far: it becomes geometry in the tessellator, so that the
//! drawing's lineweight decides its thickness.
//!
//! Widths come from [`super::font::Metrics`] and are measured in **cap
//! heights**, because a DWG text height is a cap height. See DESIGN.md section
//! 5.3 for why substitution is unavoidable here.

use super::font::{Face, Metrics};

/// Horizontal alignment, matching the DXF codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum HAlign {
    Left = 0,
    Center = 1,
    Right = 2,
    Aligned = 3,
    Middle = 4,
    Fit = 5,
}

/// Vertical alignment, matching the DXF codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum VAlign {
    Baseline = 0,
    Bottom = 1,
    Middle = 2,
    Top = 3,
}

/// One laid-out line of text, in drawing coordinates.
#[derive(Clone, Debug)]
pub struct TextRun {
    pub x: f64,
    pub y: f64,
    pub height: f64,
    pub rotation: f64,
    pub width_factor: f64,
    pub oblique: f64,
    pub rgba: u32,
    pub attr: u32,
    pub h_align: HAlign,
    pub v_align: VAlign,
    pub text: String,
    /// Which bundled face draws this run.
    pub face: super::font::Face,
    /// Position in the drawing's draw order.
    pub order: u32,
}

pub const TEXT_RECORD_BYTES: usize = 48;

/// MTEXT default line spacing, as a multiple of text height.
pub const MTEXT_LINE_SPACING: f64 = 1.66;

/// Slack on the box width before a line is broken.
///
/// Text is drawn with a substituted face whose strings are a few percent wider
/// or narrower than the font the drawing names, so a measured width that only
/// just exceeds the box says nothing. Breaking there is the worse mistake:
/// overflowing a box by a fraction is a blemish, while wrapping a line that
/// AutoCAD keeps whole moves everything below it.
const WRAP_SLACK: f64 = 1.1;

/// Break one MTEXT paragraph to a box `max_cap` cap heights wide.
///
/// Breaks at spaces only. A word wider than the box overflows it rather than
/// being split, which is what AutoCAD does, and is what keeps a scale bar's
/// "10m" label on one line when the substituted font is wider than the
/// drawing's own. Trailing spaces do not push a line over the edge.
pub fn wrap_line(line: &str, max_cap: f64, f: &Metrics) -> Vec<String> {
    if !(max_cap > 0.0) || line.is_empty() {
        return vec![line.to_string()];
    }
    let limit = max_cap * WRAP_SLACK;

    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut width = 0.0f64;

    for word in split_keeping_spaces(line) {
        let w = f.measure(word);

        // A run of spaces never forces a break: it would only hang past the
        // edge, where AutoCAD lets it sit.
        if word.starts_with(' ') {
            current.push_str(word);
            width += w;
            continue;
        }

        if !current.is_empty() && width + w > limit {
            out.push(current.trim_end_matches(' ').to_string());
            current.clear();
            width = 0.0;
        }

        current.push_str(word);
        width += w;
    }

    out.push(current);
    out
}

/// Break a line of styled runs to a box `max_cap` cap heights wide.
///
/// The break points are decided on the line as a whole, then the runs are cut
/// to match: a colour change in the middle of a sentence must not change where
/// the sentence wraps.
pub fn wrap_spans(line: &Line, max_cap: f64, f: &Metrics) -> Vec<Line> {
    let spans = &line.spans;
    let as_lines = |runs: Vec<Vec<Span>>| -> Vec<Line> {
        runs.into_iter()
            .enumerate()
            .map(|(i, spans)| Line {
                spans,
                paragraph: line.paragraph.clone(),
                // Only the first line of a wrapped paragraph is its first line.
                first: line.first && i == 0,
            })
            .collect()
    };

    if spans.is_empty() {
        return as_lines(vec![Vec::new()]);
    }
    if spans.len() == 1 {
        return as_lines(
            wrap_line(&spans[0].text, max_cap, f)
                .into_iter()
                .map(|text| {
                    vec![Span {
                        text,
                        ..spans[0].clone()
                    }]
                })
                .collect(),
        );
    }

    // Which run each character came from, so the wrapped lines can be
    // reassembled with their styles.
    let mut owner: Vec<usize> = Vec::new();
    let mut flat = String::new();
    for (i, s) in spans.iter().enumerate() {
        for c in s.text.chars() {
            flat.push(c);
            owner.push(i);
        }
    }

    let mut out: Vec<Vec<Span>> = Vec::new();
    let mut at = 0usize;
    // Indexed by position: `chars().nth` from the start for every line is
    // quadratic in a long text.
    let flat_chars: Vec<char> = flat.chars().collect();
    for wrapped in wrap_line(&flat, max_cap, f) {
        let count = wrapped.chars().count();
        // wrap_line only ever drops spaces at a break, so walk past them.
        while at < owner.len() && flat_chars.get(at) == Some(&' ') && !wrapped.starts_with(' ') {
            at += 1;
        }
        let mut runs: Vec<Span> = Vec::new();
        for (k, c) in wrapped.chars().enumerate() {
            let i = owner.get(at + k).copied().unwrap_or(spans.len() - 1);
            match runs.last_mut() {
                Some(last) if last.same_style(&spans[i]) => last.text.push(c),
                _ => runs.push(Span {
                    text: c.to_string(),
                    ..spans[i].clone()
                }),
            }
        }
        at += count;
        out.push(runs);
    }
    as_lines(out)
}

/// Split into words, with each run of spaces attached to the word before it.
fn split_keeping_spaces(line: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_space = line.starts_with(' ');
    for (i, c) in line.char_indices() {
        let is_space = c == ' ';
        if is_space != in_space {
            parts.push(&line[start..i]);
            start = i;
            in_space = is_space;
        }
    }
    if start < line.len() {
        parts.push(&line[start..]);
    }
    parts
}

/// Expand the `%%` escapes shared by TEXT, ATTRIB and MTEXT.
pub fn decode_special(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' || chars.peek() != Some(&'%') {
            out.push(c);
            continue;
        }
        chars.next(); // second '%'
        match chars.next() {
            Some('d') | Some('D') => out.push('\u{00B0}'), // degree
            Some('p') | Some('P') => out.push('\u{00B1}'), // plus/minus
            // Diameter. U+2300 is the strictly correct sign, and the bundled
            // stroke font has it, but none of Arimo, Tinos or Cousine does and
            // a missing glyph renders as tofu. The Latin-1 stroked O is in all
            // four and looks the same at drawing sizes.
            Some('c') | Some('C') => out.push('\u{00D8}'),
            // %%u, %%o and %%k toggle under/over/strike; we drop the styling.
            Some('u') | Some('U') | Some('o') | Some('O') | Some('k') | Some('K') => {}
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push('%');
                out.push(other);
            }
            None => out.push_str("%%"),
        }
    }
    out
}

/// Strip MTEXT inline formatting and split into lines.
///
/// Formatting is dropped rather than honoured: mixed fonts, per-run colour and
/// stacked fractions are a documented gap. Stacked fractions degrade to `a/b`
/// so the content survives even though the layout does not.
pub fn mtext_lines(raw: &str) -> Vec<String> {
    mtext_spans(raw)
        .into_iter()
        .map(|line| line.spans.into_iter().map(|s| s.text).collect())
        .collect()
}

/// A colour named by an MTEXT escape.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpanColor {
    Index(u8),
    Rgb(u8, u8, u8),
}

/// A height named by an MTEXT escape: a multiple of the entity's, or absolute.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpanHeight {
    Factor(f64),
    Absolute(f64),
}

/// Paragraph settings from an MTEXT `\p` code, in drawing units.
///
/// The code is not documented by Autodesk; this follows the arguments the
/// format is widely understood to use: `l` a left indent applying to every
/// line, `i` an extra indent on the first line only, and `t` a list of tab
/// stops. `q` justification and `x` line spacing are read and ignored.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Paragraph {
    pub indent: f64,
    pub first_indent: f64,
    pub tabs: Vec<f64>,
}

/// One laid-out line: its runs and the paragraph settings in force.
#[derive(Clone, Debug, Default)]
pub struct Line {
    pub spans: Vec<Span>,
    pub paragraph: Paragraph,
    /// This line begins a paragraph, so the first-line indent applies.
    pub first: bool,
}

/// A run of MTEXT with uniform styling.
#[derive(Clone, Debug, PartialEq)]
pub struct Span {
    pub text: String,
    /// Colour override from `\C` or `\c`. None means the entity's own.
    pub color: Option<SpanColor>,
    /// Face override from `\f` or `\F`. None means the entity's own style.
    pub face: Option<Face>,
    pub height: SpanHeight,
    pub underline: bool,
    pub overline: bool,
    pub strike: bool,
}

impl Default for Span {
    fn default() -> Span {
        Span {
            text: String::new(),
            color: None,
            face: None,
            height: SpanHeight::Factor(1.0),
            underline: false,
            overline: false,
            strike: false,
        }
    }
}

impl Span {
    pub fn same_style(&self, other: &Span) -> bool {
        self.color == other.color
            && self.face == other.face
            && self.height == other.height
            && self.underline == other.underline
            && self.overline == other.overline
            && self.strike == other.strike
    }
}

/// Strip MTEXT inline formatting and split into lines of styled runs.
///
/// Colour, height and the three rules (under, over, strike) are kept, since
/// they change what the sheet says: a legend entry written in colour 30 and
/// underlined is not the same as the body text around it. A font change picks
/// which bundled face draws the run (DESIGN.md section 5.3), and paragraph
/// indents and tabs are read; width, tracking, oblique and alignment codes are
/// dropped.
/// Stacked fractions degrade to `a/b` so the content survives even though the
/// layout does not.
pub fn mtext_spans(raw: &str) -> Vec<Line> {
    let mut lines: Vec<Line> = vec![Line {
        first: true,
        ..Line::default()
    }];
    let mut style = Span::default();
    // Braces scope a style change; the stack restores what was in force.
    let mut stack: Vec<Span> = Vec::new();
    let mut chars = raw.chars().peekable();

    // Collect the characters up to the ';' that closes a setting.
    let argument = |chars: &mut std::iter::Peekable<std::str::Chars>| {
        let mut body = String::new();
        for ch in chars.by_ref() {
            if ch == ';' {
                break;
            }
            body.push(ch);
        }
        body
    };

    let push_char = |lines: &mut Vec<Line>, style: &Span, c: char| {
        let line = &mut lines.last_mut().unwrap().spans;
        match line.last_mut() {
            Some(last) if last.same_style(style) => last.text.push(c),
            _ => {
                let mut s = style.clone();
                s.text.push(c);
                line.push(s);
            }
        }
    };
    let push_str = |lines: &mut Vec<Line>, style: &Span, s: &str| {
        for c in s.chars() {
            push_char(lines, style, c);
        }
    };

    while let Some(c) = chars.next() {
        match c {
            '{' => stack.push(style.clone()),
            '}' => style = stack.pop().unwrap_or_default(),
            '\\' => {
                let Some(code) = chars.next() else { break };
                match code {
                    'P' => {
                        // A new paragraph keeps the settings in force.
                        let paragraph = lines.last().unwrap().paragraph.clone();
                        lines.push(Line {
                            paragraph,
                            first: true,
                            ..Line::default()
                        });
                    }
                    // Escaped literals.
                    '\\' => push_char(&mut lines, &style, '\\'),
                    '{' => push_char(&mut lines, &style, '{'),
                    '}' => push_char(&mut lines, &style, '}'),
                    '~' => push_char(&mut lines, &style, '\u{00A0}'),
                    // Stacked fraction: \S<upper>^<lower>; becomes upper/lower.
                    'S' => {
                        let body = argument(&mut chars).replacen(['^', '#'], "/", 1);
                        push_str(&mut lines, &style, body.trim_end_matches('/'));
                    }
                    // Colour by index, and by true colour.
                    'C' => {
                        let body = argument(&mut chars);
                        // 0 is ByBlock and 256 ByLayer: back to the entity's
                        // own colour either way.
                        style.color = match body.trim().parse::<u32>() {
                            Ok(0) | Ok(256) | Err(_) => None,
                            Ok(n) => Some(SpanColor::Index(n.min(255) as u8)),
                        };
                    }
                    'c' => {
                        let body = argument(&mut chars);
                        style.color = body.trim().parse::<u32>().ok().map(|n| {
                            // Stored as 0x00BBGGRR, the way AutoCAD writes it.
                            SpanColor::Rgb(
                                (n & 0xFF) as u8,
                                ((n >> 8) & 0xFF) as u8,
                                ((n >> 16) & 0xFF) as u8,
                            )
                        });
                    }
                    // `\H2x;` is twice the current height, `\H2;` is two units.
                    'H' => {
                        let body = argument(&mut chars);
                        let relative = body.ends_with('x') || body.ends_with('X');
                        let n: f64 = body
                            .trim_end_matches(['x', 'X'])
                            .trim()
                            .parse()
                            .unwrap_or(1.0);
                        if n.is_finite() && n > 0.0 {
                            style.height = if relative {
                                match style.height {
                                    // Nested relative changes compound.
                                    SpanHeight::Factor(f) => SpanHeight::Factor(f * n),
                                    SpanHeight::Absolute(h) => SpanHeight::Absolute(h * n),
                                }
                            } else {
                                SpanHeight::Absolute(n)
                            };
                        }
                    }
                    'p' => {
                        let body = argument(&mut chars);
                        lines.last_mut().unwrap().paragraph = parse_paragraph(&body);
                    }
                    // A font change. `\f` names a typeface, `\F` a font file;
                    // AutoCAD exports the first and parses both. The name
                    // decides which of the bundled faces draws the run, and it
                    // is the code that puts a condensed face on exactly the
                    // title-block fields that collide when it is ignored.
                    'f' => {
                        let body = argument(&mut chars);
                        style.face = Some(super::font::resolve_override(&body));
                    }
                    'F' => {
                        let body = argument(&mut chars);
                        style.face = Some(super::font::resolve_file(&body));
                    }
                    // Settings that do not survive font substitution.
                    'W' | 'Q' | 'A' | 'T' | 'h' => {
                        argument(&mut chars);
                    }
                    // `\U+XXXX` is how a codepoint outside the drawing's code
                    // page is written. Left undecoded it shows as literal text.
                    'U' if chars.peek() == Some(&'+') => {
                        chars.next();
                        let mut hex = String::new();
                        for _ in 0..4 {
                            match chars.peek() {
                                Some(c) if c.is_ascii_hexdigit() => {
                                    hex.push(*c);
                                    chars.next();
                                }
                                _ => break,
                            }
                        }
                        match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                            Some(c) => push_char(&mut lines, &style, c),
                            None => {
                                push_str(&mut lines, &style, "\\U+");
                                push_str(&mut lines, &style, &hex);
                            }
                        }
                    }
                    'L' => style.underline = true,
                    'l' => style.underline = false,
                    'O' => style.overline = true,
                    'o' => style.overline = false,
                    'K' => style.strike = true,
                    'k' => style.strike = false,
                    'N' => {}
                    other => push_char(&mut lines, &style, other),
                }
            }
            c => push_char(&mut lines, &style, c),
        }
    }

    for line in &mut lines {
        for span in line.spans.iter_mut() {
            span.text = decode_special(&span.text);
        }
        line.spans.retain(|s| !s.text.is_empty());
    }
    lines
}

/// Read an MTEXT `\p` argument list: `xi-3,l4,t4` and the like.
///
/// Values are in drawing units. A leading `x` and the `q` justification letter
/// are consumed and ignored; anything unrecognised is skipped rather than
/// guessed at, since the code is not documented by Autodesk.
fn parse_paragraph(body: &str) -> Paragraph {
    let mut p = Paragraph::default();
    for part in body.trim_start_matches(['x', 'X']).split(',') {
        let part = part.trim();
        let Some(key) = part.chars().next() else {
            continue;
        };
        let value = part[key.len_utf8()..].trim();
        match key {
            'i' => p.first_indent = value.parse().unwrap_or(0.0),
            'l' => p.indent = value.parse().unwrap_or(0.0),
            't' => {
                // Each stop can carry a trailing alignment letter.
                let number = value.trim_end_matches(|c: char| c.is_ascii_alphabetic());
                if let Ok(v) = number.parse::<f64>() {
                    if v.is_finite() {
                        p.tabs.push(v);
                    }
                }
            }
            _ => {}
        }
    }
    p.tabs
        .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    p
}

/// Vertical offset of the first baseline from the attachment point, and the
/// horizontal alignment implied by an MTEXT attachment code (1..=9).
///
/// Returns `(h_align, first_baseline_dy)` where dy is added to the anchor's y.
pub fn mtext_layout(attachment: u8, line_count: usize, height: f64, spacing: f64) -> (HAlign, f64) {
    let h = match attachment {
        1 | 4 | 7 => HAlign::Left,
        2 | 5 | 8 => HAlign::Center,
        _ => HAlign::Right,
    };
    let n = line_count.max(1) as f64;
    // Text grows downward from the first baseline.
    let dy = match attachment {
        1..=3 => -height,                                  // top row
        4..=6 => (n - 1.0) * spacing / 2.0 - height / 2.0, // middle row
        _ => (n - 1.0) * spacing,                          // bottom row
    };
    (h, dy)
}

/// Serialise runs into the wire format: fixed records plus a UTF-8 string blob.
///
/// Record layout, little-endian, `TEXT_RECORD_BYTES` each:
/// `f32 x, y, height, rotation, widthFactor, oblique | u32 rgba, attr, strOffset | u16 strLen | u8 hAlign, vAlign | u32 order | u8 face | 3 bytes padding`
pub fn encode(runs: &[TextRun], origin: [f64; 2]) -> (Vec<u8>, Vec<u8>) {
    let mut records = Vec::with_capacity(runs.len() * TEXT_RECORD_BYTES);
    let mut blob: Vec<u8> = Vec::new();

    for r in runs {
        let bytes = r.text.as_bytes();
        // A single run longer than u16 is pathological; clamp on a char
        // boundary so the blob stays valid UTF-8.
        let mut len = bytes.len().min(u16::MAX as usize);
        while len > 0 && !r.text.is_char_boundary(len) {
            len -= 1;
        }
        let offset = blob.len() as u32;
        blob.extend_from_slice(&bytes[..len]);

        records.extend_from_slice(&((r.x - origin[0]) as f32).to_le_bytes());
        records.extend_from_slice(&((r.y - origin[1]) as f32).to_le_bytes());
        records.extend_from_slice(&(r.height as f32).to_le_bytes());
        records.extend_from_slice(&(r.rotation as f32).to_le_bytes());
        records.extend_from_slice(&(r.width_factor as f32).to_le_bytes());
        records.extend_from_slice(&(r.oblique as f32).to_le_bytes());
        records.extend_from_slice(&r.rgba.to_le_bytes());
        records.extend_from_slice(&r.attr.to_le_bytes());
        records.extend_from_slice(&offset.to_le_bytes());
        records.extend_from_slice(&(len as u16).to_le_bytes());
        records.push(r.h_align as u8);
        records.push(r.v_align as u8);
        records.extend_from_slice(&r.order.to_le_bytes());
        records.push(r.face.to_byte());
        records.extend_from_slice(&[0, 0, 0]);
    }

    debug_assert_eq!(records.len(), runs.len() * TEXT_RECORD_BYTES);
    (records, blob)
}

#[cfg(test)]
mod spans {
    use super::*;

    fn one_line(raw: &str) -> Line {
        let mut lines = mtext_spans(raw);
        assert_eq!(lines.len(), 1, "{raw:?} gave {} lines", lines.len());
        lines.remove(0)
    }

    fn one(raw: &str) -> Vec<Span> {
        one_line(raw).spans
    }

    #[test]
    fn plain_text_is_one_unstyled_run() {
        let s = one("PLANCHER HAUT");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].text, "PLANCHER HAUT");
        assert_eq!(s[0].color, None);
        assert_eq!(s[0].height, SpanHeight::Factor(1.0));
        assert!(!s[0].underline);
    }

    #[test]
    fn a_colour_escape_styles_what_follows_it() {
        // As a title block writes its heading.
        let s = one("\\pxqc;{\\fArial Nova|b0|i1|c0|p34;\\L\\C30;PLAN DU REZ-DE-CHAUSSEE}");
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].text, "PLAN DU REZ-DE-CHAUSSEE");
        assert_eq!(s[0].color, Some(SpanColor::Index(30)));
        assert!(s[0].underline);
    }

    #[test]
    fn a_brace_scopes_the_style_it_sets() {
        let s = one("garage {\\H0.75x;(existant)} suite");
        assert_eq!(s.len(), 3, "{s:?}");
        assert_eq!(s[0].text, "garage ");
        assert_eq!(s[0].height, SpanHeight::Factor(1.0));
        assert_eq!(s[1].text, "(existant)");
        assert_eq!(s[1].height, SpanHeight::Factor(0.75));
        // Closing the brace puts the earlier height back.
        assert_eq!(s[2].text, " suite");
        assert_eq!(s[2].height, SpanHeight::Factor(1.0));
    }

    #[test]
    fn a_height_without_x_is_an_absolute_height() {
        let s = one("a{\\H2.5;big}");
        assert_eq!(s[1].height, SpanHeight::Absolute(2.5));
    }

    #[test]
    fn colour_zero_and_two_five_six_fall_back_to_the_entity() {
        assert_eq!(one("{\\C256;x}")[0].color, None);
        assert_eq!(one("{\\C0;x}")[0].color, None);
        assert_eq!(one("{\\C7;x}")[0].color, Some(SpanColor::Index(7)));
    }

    #[test]
    fn a_true_colour_escape_reads_as_rgb() {
        // \c is written as 0x00BBGGRR.
        assert_eq!(
            one("{\\c255;x}")[0].color,
            Some(SpanColor::Rgb(255, 0, 0)),
            "low byte is red"
        );
    }

    #[test]
    fn paragraph_breaks_still_split_lines_and_keep_the_style() {
        let lines = mtext_spans("{\\C7;first\\Psecond}");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].spans[0].text, "first");
        assert_eq!(lines[1].spans[0].text, "second");
        assert_eq!(lines[1].spans[0].color, Some(SpanColor::Index(7)));
    }

    #[test]
    fn the_plain_line_view_matches_the_spans() {
        let raw = "chaufferie\\P{\\H0.66667x;< à 70KW}";
        assert_eq!(mtext_lines(raw), vec!["chaufferie", "< à 70KW"]);
    }

    #[test]
    fn paragraph_settings_are_read_from_the_p_code() {
        // As a bulleted note block writes it.
        let line = one_line("\\pxi-3,l4,t4;-\tsomething");
        assert_eq!(line.paragraph.first_indent, -3.0);
        assert_eq!(line.paragraph.indent, 4.0);
        assert_eq!(line.paragraph.tabs, vec![4.0]);
        // The tab itself stays in the text for the layout to act on.
        let text: String = line.spans.iter().map(|s| s.text.as_str()).collect();
        assert!(text.contains('\t'), "{text:?}");
    }

    #[test]
    fn several_tab_stops_are_read_in_order() {
        let line = one_line("\\pt10,t30,t20;a");
        assert_eq!(line.paragraph.tabs, vec![10.0, 20.0, 30.0]);
    }

    #[test]
    fn an_unreadable_paragraph_code_leaves_the_defaults() {
        let line = one_line("\\pqc;a");
        assert_eq!(line.paragraph, Paragraph::default());
        assert_eq!(line.spans[0].text, "a");
    }

    #[test]
    fn paragraph_settings_carry_to_the_next_line() {
        let lines = mtext_spans("\\pl4;first\\Psecond");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].paragraph.indent, 4.0);
        assert!(lines[1].first, "a P break starts a new paragraph");
    }

    #[test]
    fn styled_runs_wrap_as_one_line_of_text() {
        let f = Metrics::for_face(Face::TrueType(super::super::font::TrueTypeFace {
            family: super::super::font::Family::Mono,
            bold: false,
            italic: false,
        }));
        let line = one_line("{\\C7;aaaa }bbbb cccc");
        // "aaaa bbbb" is 9 characters, "aaaa bbbb cccc" is 14.
        let wrapped = wrap_spans(&line, 10.0 * f.advance('a') / WRAP_SLACK, &f);
        assert_eq!(wrapped.len(), 2, "{wrapped:?}");
        let text: String = wrapped[0].spans.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(text, "aaaa bbbb");
        // The colour survives the split.
        assert_eq!(wrapped[0].spans[0].color, Some(SpanColor::Index(7)));
        assert_eq!(wrapped[0].spans[1].color, None);
        // Only the first of the wrapped lines starts the paragraph.
        assert!(wrapped[0].first);
        assert!(!wrapped[1].first);
    }
}

#[cfg(test)]
mod wrapping {
    use super::super::font::{Family, TrueTypeFace};
    use super::*;

    /// The bundled monospaced face, so a box width can be stated in characters.
    fn fixed() -> Metrics {
        Metrics::for_face(Face::TrueType(TrueTypeFace {
            family: Family::Mono,
            bold: false,
            italic: false,
        }))
    }

    /// Each wrapped line looked up the character at its start by counting from
    /// the start of the text: a long paragraph in several runs was quadratic.
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "timing")]
    fn a_long_paragraph_of_several_runs_is_wrapped_in_linear_time() {
        let f = fixed();
        let raw = format!("{{\\C7;{}}}{}", "ab ".repeat(40_000), "cd ".repeat(40_000));
        let lines = mtext_spans(&raw);
        let t = std::time::Instant::now();
        let wrapped = wrap_spans(&lines[0], box_for(5), &f);
        assert!(t.elapsed().as_millis() < 500, "took {:?}", t.elapsed());
        // Five characters to a line holds "ab ab" and "cd cd": one word is
        // always left over to the next line's start.
        assert!(wrapped.len() > 30_000, "{} lines", wrapped.len());
        let first: String = wrapped[0].spans.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(first, "ab ab");
    }

    /// A box, in cap heights, that admits exactly `chars` monospaced characters
    /// once `WRAP_SLACK` has been applied. The half-character keeps the
    /// comparison off an exact float boundary.
    fn box_for(chars: usize) -> f64 {
        (chars as f64 + 0.5) * fixed().advance('a') / WRAP_SLACK
    }

    #[test]
    fn a_paragraph_breaks_at_spaces() {
        let f = fixed();
        // "the quick brown fox" is 19 characters; adding " jumps" is 25.
        let lines = wrap_line("the quick brown fox jumps", box_for(20), &f);
        assert_eq!(lines, vec!["the quick brown fox", "jumps"]);
    }

    #[test]
    fn a_line_that_fits_is_left_alone() {
        let f = fixed();
        assert_eq!(wrap_line("short", box_for(20), &f), vec!["short"]);
        // No box width means no wrapping at all.
        assert_eq!(wrap_line("a very long line indeed", 0.0, &f).len(), 1);
    }

    #[test]
    fn a_word_too_long_for_the_box_overflows_it_rather_than_splitting() {
        let f = fixed();
        // The scale bar case: "10m" needs three characters in a two-character
        // box, and measures wider still once substituted. AutoCAD leaves it.
        assert_eq!(wrap_line("10m", box_for(2), &f), vec!["10m"]);
        assert_eq!(
            wrap_line("antidisestablishmentarianism", box_for(6), &f),
            vec!["antidisestablishmentarianism"]
        );
        // Following words still wrap normally.
        let lines = wrap_line("antidisestablishmentarianism is long", box_for(6), &f);
        assert_eq!(lines.len(), 3, "{lines:?}");
    }

    /// The slack that covers the difference between the drawing's font and the
    /// substitute: overflowing a box by a fraction is a blemish, but wrapping a
    /// line AutoCAD keeps whole moves everything below it.
    #[test]
    fn a_line_that_only_just_overflows_is_left_alone() {
        let f = fixed();
        let w = f.advance('a');
        // Eight characters against a box of exactly eight, then shrunk by less
        // than the slack allows.
        assert_eq!(
            wrap_line("aaaa bbb", 8.0 * w / WRAP_SLACK, &f),
            vec!["aaaa bbb"]
        );
        // Well past the slack, and it breaks.
        assert_eq!(wrap_line("aaaa bbb", 5.0 * w, &f), vec!["aaaa", "bbb"]);
    }

    #[test]
    fn trailing_spaces_do_not_push_a_line_over() {
        let f = fixed();
        // "abcd" plus four spaces is twice the box; the spaces must not break
        // a line of their own.
        assert_eq!(wrap_line("abcd    ", box_for(4), &f), vec!["abcd    "]);
    }

    #[test]
    fn every_character_survives_the_wrap() {
        let f = fixed();
        let text = "PLANCHER HAUT SOUS-SOL - ISOLATION THERMIQUE 120mm";
        let joined = wrap_line(text, box_for(16), &f).join(" ");
        assert_eq!(
            joined.split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>()
        );
    }

    /// Wrapping must not depend on the face having been measured by a host:
    /// the widths are compiled in, so the same text breaks the same way
    /// wherever it runs.
    #[test]
    fn wrapping_needs_nothing_from_the_host() {
        let text = "PLANCHER HAUT SOUS-SOL - ISOLATION THERMIQUE 120mm";
        for face in [
            Face::Stroke,
            Face::default(),
            Face::TrueType(TrueTypeFace {
                family: Family::Serif,
                bold: true,
                italic: false,
            }),
        ] {
            let m = Metrics::for_face(face);
            let lines = wrap_line(text, 20.0, &m);
            assert!(lines.len() > 1, "{face:?} did not wrap at all");
            assert_eq!(lines.join(" "), text);
        }
    }

    /// A proportional face breaks differently from a monospaced one, which is
    /// the whole reason for resolving the face before wrapping.
    #[test]
    fn the_face_decides_where_a_line_breaks() {
        // All narrow letters, so the proportional face is much the shorter.
        let text = "illilli illilli";
        let mono = fixed();
        let sans = Metrics::for_face(Face::default());
        assert!(
            sans.measure(text) < mono.measure(text),
            "narrow letters should measure less proportionally"
        );

        // A box between the two: wide enough for one line of the proportional
        // face, too narrow for one line of the fixed one.
        let box_cap = (sans.measure(text) + mono.measure(text)) / 2.0 / WRAP_SLACK;
        assert_eq!(wrap_line(text, box_cap, &sans), vec![text]);
        assert_eq!(wrap_line(text, box_cap, &mono), vec!["illilli", "illilli"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_codes_become_symbols() {
        assert_eq!(decode_special("45%%d"), "45\u{00B0}");
        assert_eq!(decode_special("%%p0.5"), "\u{00B1}0.5");
        assert_eq!(decode_special("%%c20"), "\u{00D8}20");
    }

    #[test]
    fn underline_toggles_vanish_without_eating_text() {
        assert_eq!(decode_special("%%uSOUS-SOL%%u"), "SOUS-SOL");
    }

    #[test]
    fn three_percent_signs_are_one() {
        // AutoCAD's control codes reference: %%% draws a single percent sign.
        assert_eq!(decode_special("50%%%"), "50%");
        assert_eq!(decode_special("%%%%c50"), "%%c50");
    }

    #[test]
    fn unknown_percent_codes_are_left_alone() {
        assert_eq!(decode_special("%%z"), "%%z");
        assert_eq!(decode_special("100% done"), "100% done");
    }

    #[test]
    fn mtext_splits_on_paragraph_marks() {
        assert_eq!(mtext_lines(r"one\Ptwo\Pthree"), vec!["one", "two", "three"]);
    }

    #[test]
    fn mtext_drops_font_and_height_codes() {
        let raw = r"{\fArial|b0|i0|c0|p34;\H2.5;Salle de bains}";
        assert_eq!(mtext_lines(raw), vec!["Salle de bains"]);
    }

    #[test]
    fn mtext_drops_colour_and_width_codes() {
        assert_eq!(mtext_lines(r"\C1;RED\C256;back"), vec!["REDback"]);
        assert_eq!(mtext_lines(r"\W0.8;narrow"), vec!["narrow"]);
    }

    #[test]
    fn mtext_keeps_escaped_literals() {
        assert_eq!(mtext_lines(r"a\\b"), vec![r"a\b"]);
        assert_eq!(mtext_lines(r"a\{b\}"), vec!["a{b}"]);
    }

    #[test]
    fn mtext_stacked_fraction_degrades_to_a_slash() {
        assert_eq!(mtext_lines(r"\S1^2;"), vec!["1/2"]);
        assert_eq!(
            mtext_lines(r"niveau \S+0.00^-0.15; m"),
            vec!["niveau +0.00/-0.15 m"]
        );
    }

    #[test]
    fn mtext_handles_accented_content() {
        // This file is French; dropping non-ASCII would be very visible.
        assert_eq!(mtext_lines("Cuisine aménagée"), vec!["Cuisine aménagée"]);
    }

    #[test]
    fn mtext_decodes_codepoint_escapes() {
        assert_eq!(
            mtext_lines(r"Rez-de-chauss\U+00E9e"),
            vec!["Rez-de-chaussée"]
        );
        assert_eq!(mtext_lines(r"\U+00B10.5"), vec!["\u{00B1}0.5"]);
        // Lower-case hex and a following digit that is not part of the escape.
        assert_eq!(mtext_lines(r"\U+00e9tage 2"), vec!["étage 2"]);
    }

    #[test]
    fn a_malformed_codepoint_escape_is_left_visible() {
        assert_eq!(mtext_lines(r"\U+ZZZZ"), vec!["\\U+ZZZZ"]);
    }

    #[test]
    fn mtext_survives_a_truncated_escape() {
        assert_eq!(mtext_lines("abc\\"), vec!["abc"]);
        // Unterminated ';' code swallows the rest rather than panicking.
        assert_eq!(mtext_lines(r"\H2.5"), vec![""]);
    }

    #[test]
    fn attachment_maps_to_horizontal_alignment() {
        assert_eq!(mtext_layout(1, 1, 1.0, 1.66).0, HAlign::Left);
        assert_eq!(mtext_layout(5, 1, 1.0, 1.66).0, HAlign::Center);
        assert_eq!(mtext_layout(9, 1, 1.0, 1.66).0, HAlign::Right);
    }

    #[test]
    fn top_attachment_puts_the_first_baseline_below_the_anchor() {
        let (_, dy) = mtext_layout(2, 3, 2.0, 3.32);
        assert!((dy + 2.0).abs() < 1e-9, "dy {dy}");
    }

    #[test]
    fn bottom_attachment_puts_the_last_baseline_on_the_anchor() {
        let n = 3;
        let spacing = 3.32;
        let (_, dy) = mtext_layout(8, n, 2.0, spacing);
        // Last baseline sits at dy - (n-1)*spacing, which must land on 0.
        let last = dy - (n as f64 - 1.0) * spacing;
        assert!(last.abs() < 1e-9, "last baseline {last}");
    }

    #[test]
    fn middle_attachment_centres_the_block() {
        let n = 4;
        let spacing = 3.32;
        let height = 2.0;
        let (_, dy) = mtext_layout(5, n, height, spacing);
        let first = dy;
        let last = dy - (n as f64 - 1.0) * spacing;
        // Cap-top of the first line and baseline of the last straddle the anchor.
        let centre = ((first + height) + last) / 2.0;
        assert!(centre.abs() < 1e-9, "block centre {centre}");
    }

    #[test]
    fn encode_produces_the_documented_stride_and_valid_utf8() {
        let runs = vec![
            TextRun {
                x: 10.0,
                y: 20.0,
                height: 2.5,
                rotation: 0.0,
                width_factor: 1.0,
                oblique: 0.0,
                rgba: 0xFF00FF00,
                attr: 7,
                h_align: HAlign::Center,
                v_align: VAlign::Middle,
                text: "Chambre 1".into(),
                face: Face::default(),
                order: 1,
            },
            TextRun {
                x: 0.0,
                y: 0.0,
                height: 1.0,
                rotation: 0.0,
                width_factor: 1.0,
                oblique: 0.0,
                rgba: 0,
                attr: 0,
                h_align: HAlign::Left,
                v_align: VAlign::Baseline,
                text: "aménagée".into(),
                face: Face::default(),
                order: 2,
            },
        ];
        let (rec, blob) = encode(&runs, [0.0, 0.0]);
        assert_eq!(rec.len(), 2 * TEXT_RECORD_BYTES);
        assert_eq!(std::str::from_utf8(&blob).unwrap(), "Chambre 1aménagée");

        // Second record's offset must point at the second string.
        let off = u32::from_le_bytes(
            rec[TEXT_RECORD_BYTES + 32..TEXT_RECORD_BYTES + 36]
                .try_into()
                .unwrap(),
        );
        let len = u16::from_le_bytes(
            rec[TEXT_RECORD_BYTES + 36..TEXT_RECORD_BYTES + 38]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            std::str::from_utf8(&blob[off as usize..off as usize + len as usize]).unwrap(),
            "aménagée"
        );
        assert_eq!(rec[TEXT_RECORD_BYTES + 38], HAlign::Left as u8);
        assert_eq!(rec[TEXT_RECORD_BYTES + 39], VAlign::Baseline as u8);
    }

    #[test]
    fn encode_subtracts_the_origin() {
        let runs = vec![TextRun {
            x: 6_500_000.0,
            y: 100.0,
            height: 1.0,
            rotation: 0.0,
            width_factor: 1.0,
            oblique: 0.0,
            rgba: 0,
            attr: 0,
            h_align: HAlign::Left,
            v_align: VAlign::Baseline,
            text: "x".into(),
            face: Face::default(),
            order: 1,
        }];
        let (rec, _) = encode(&runs, [6_500_000.0, 0.0]);
        let x = f32::from_le_bytes(rec[0..4].try_into().unwrap());
        assert!(
            x.abs() < 1e-3,
            "x {x} should be near zero after the origin shift"
        );
    }
}
