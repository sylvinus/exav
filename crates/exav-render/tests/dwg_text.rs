//! How text is placed: frames that carry mirroring and stretching, the
//! alignments, MTEXT's formatting. On drawings of
//! `tests/fixtures/dwg/make.py`, checked against what the script put in.

#![cfg(feature = "dwg")]

mod cad_common;

use exav_render::dwg::{Document, Drawing, STROKE_BYTES, TEXT_RECORD_BYTES};

fn fixture(name: &str) -> Document {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dwg")
        .join(format!("{name}.gz"));
    let gz = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Document::parse(&cad_common::gunzip(&gz)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn f32_at(b: &[u8], i: usize) -> f64 {
    f64::from(f32::from_le_bytes(b[i..i + 4].try_into().unwrap()))
}

/// A text record as the renderer gets it, in world coordinates.
#[derive(Debug)]
struct Run {
    text: String,
    at: [f64; 2],
    u: [f64; 2],
    v: [f64; 2],
    h_align: u8,
    v_align: u8,
}

fn runs(d: &Drawing) -> Vec<Run> {
    d.texts
        .chunks(TEXT_RECORD_BYTES)
        .map(|r| {
            let at = u32::from_le_bytes(r[32..36].try_into().unwrap()) as usize;
            let len = u16::from_le_bytes(r[36..38].try_into().unwrap()) as usize;
            Run {
                text: String::from_utf8_lossy(&d.text_strings[at..at + len]).into_owned(),
                at: [f32_at(r, 0) + d.origin[0], f32_at(r, 4) + d.origin[1]],
                u: [f32_at(r, 8), f32_at(r, 12)],
                v: [f32_at(r, 16), f32_at(r, 20)],
                h_align: r[38],
                v_align: r[39],
            }
        })
        .collect()
}

fn run<'a>(all: &'a [Run], text: &str, near: [f64; 2]) -> &'a Run {
    all.iter()
        .filter(|r| r.text == text)
        .min_by(|a, b| {
            let d = |r: &Run| (r.at[0] - near[0]).hypot(r.at[1] - near[1]);
            d(a).total_cmp(&d(b))
        })
        .unwrap_or_else(|| panic!("no {text:?} in {all:?}"))
}

/// Endpoints of the strokes inside a box.
fn ink(d: &Drawing, min: [f64; 2], max: [f64; 2]) -> Vec<[f64; 2]> {
    d.strokes
        .as_chunks::<STROKE_BYTES>()
        .0
        .iter()
        .flat_map(|s| {
            let (ox, oy) = (d.origin[0], d.origin[1]);
            [
                [f32_at(s, 0) + ox, f32_at(s, 4) + oy],
                [f32_at(s, 8) + ox, f32_at(s, 12) + oy],
            ]
        })
        .filter(|p| p[0] >= min[0] && p[0] <= max[0] && p[1] >= min[1] && p[1] <= max[1])
        .collect()
}

fn bounds(ps: &[[f64; 2]]) -> [f64; 4] {
    let lo = |i: usize| ps.iter().map(|p| p[i]).fold(f64::INFINITY, f64::min);
    let hi = |i: usize| ps.iter().map(|p| p[i]).fold(f64::NEG_INFINITY, f64::max);
    [lo(0), lo(1), hi(0), hi(1)]
}

fn close(a: [f64; 2], b: [f64; 2]) -> bool {
    (a[0] - b[0]).abs() < 1e-4 && (a[1] - b[1]).abs() < 1e-4
}

/// A block inserted mirrored mirrors its text; one stretched in x stretches
/// it along the baseline only.
#[test]
fn a_blocks_scale_mirrors_and_stretches_its_text() {
    let d = fixture("text_frames.dxf").tessellate(None, None);
    let all = runs(&d);
    let mirrored = run(&all, "LABEL", [100.0, 0.0]);
    assert!(close(mirrored.at, [100.0, 0.0]), "{mirrored:?}");
    assert!(
        close(mirrored.u, [-2.5, 0.0]) && close(mirrored.v, [0.0, 2.5]),
        "{mirrored:?}"
    );
    let stretched = run(&all, "LABEL", [100.0, 20.0]);
    assert!(
        close(stretched.u, [5.0, 0.0]) && close(stretched.v, [0.0, 2.5]),
        "{stretched:?}"
    );
    // The stroke font's copy, drawn here: leftwards from the insertion.
    let b = bounds(&ink(&d, [80.0, -6.0], [120.0, -1.0]));
    assert!(b[2] <= 100.0 + 1e-6 && b[0] < 90.0, "{b:?}");
}

/// TEXT's generation flags: 2 backward, 4 upside down.
#[test]
fn backward_and_upside_down_text_is_mirrored() {
    let d = fixture("text_frames.dxf").tessellate(None, None);
    let all = runs(&d);
    let back = run(&all, "BACKWARD", [150.0, 0.0]);
    assert!(
        close(back.u, [-2.5, 0.0]) && close(back.v, [0.0, 2.5]),
        "{back:?}"
    );
    let upside = run(&all, "UPSIDE", [150.0, 10.0]);
    assert!(
        close(upside.u, [2.5, 0.0]) && close(upside.v, [0.0, -2.5]),
        "{upside:?}"
    );
    let b = bounds(&ink(&d, [130.0, 19.0], [170.0, 24.0]));
    assert!(b[2] <= 150.0 + 1e-6 && b[0] < 145.0, "{b:?}");
}

/// Bottom puts the descenders on the anchor: the baseline a third of the
/// height above it in the stroke font. TEXT's MIDDLE centres capitals and
/// descenders together. An outline run says Bottom; its renderer places it.
#[test]
fn bottom_and_middle_text_sit_where_autocad_puts_them() {
    let d = fixture("text_frames.dxf").tessellate(None, None);
    let low = bounds(&ink(&d, [199.0, 9.0], [215.0, 15.0]));
    assert!((low[1] - 11.0).abs() < 0.05, "{low:?}");
    // 3 high, descent 1: from 19 (baseline) to 22 (capitals).
    let middle = bounds(&ink(&d, [190.0, 17.0], [215.0, 23.0]));
    assert!(
        (middle[1] - 19.0).abs() < 0.05 && (middle[3] - 22.0).abs() < 0.1,
        "{middle:?}"
    );
    let all = runs(&d);
    let bottom = run(&all, "BOTTOM", [200.0, 0.0]);
    assert_eq!((bottom.h_align, bottom.v_align), (0, 1));
}

/// A symbol font's letters are the symbols they draw; text the stroke font
/// cannot draw (Chinese in an SHX style) goes to an outline face; `%%nnn` is
/// a character; a constant ATTDEF is drawn unless it is invisible.
#[test]
fn symbols_and_characters_the_stroke_font_lacks() {
    let d = fixture("text_symbols.dxf").tessellate(None, None);
    let all = runs(&d);
    let texts: Vec<&str> = all.iter().map(|r| r.text.as_str()).collect();
    assert!(
        texts.contains(&"中文标注") && texts.contains(&"αβγ"),
        "{texts:?}"
    );
    assert!(!texts.contains(&"abg"), "{texts:?}");
    // "AB" in the stroke font, 2.5 high: about two capitals wide.
    let ab = bounds(&ink(&d, [-1.0, 39.0], [20.0, 43.0]));
    assert!(ab[2] > 2.5 && ab[2] < 6.0, "{ab:?}");
    assert!(
        !ink(&d, [-1.0, 59.0], [30.0, 63.0]).is_empty(),
        "the constant ATTDEF"
    );
    assert!(
        ink(&d, [-1.0, 54.0], [30.0, 58.0]).is_empty(),
        "the invisible one"
    );
}

fn order(r: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(r[at..at + 4].try_into().unwrap())
}

/// MTEXT takes its style's width factor and slant, `\W` `\Q` `\T` per run,
/// `\pqc` centres a paragraph in the box, a stack is drawn small above and
/// below a bar, and a multiline ATTRIB and a MULTILEADER's text are MTEXT.
#[test]
fn mtext_formatting_is_drawn() {
    let d = fixture("text_mtext.dxf").tessellate(None, None);
    let all = runs(&d);
    let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
    let wide = run(&all, "WIDE MTEXT", [0.0, 0.0]);
    assert!(
        close(wide.u, [5.0, 0.0]) && close(wide.v, [0.0, 2.5]),
        "{wide:?}"
    );
    let slanted = run(&all, "OBL MTEXT", [0.0, 10.0]);
    assert!(
        near(slanted.v[0], 2.5 * 30f64.to_radians().tan()),
        "{slanted:?}"
    );
    let half = run(&all, "half", [0.0, 20.0]);
    assert!(close(half.u, [1.25, 0.0]), "{half:?}");
    let slant = run(&all, "slant", [0.0, 20.0]);
    assert!(
        near(slant.v[0], 2.5 * 20f64.to_radians().tan()),
        "{slant:?}"
    );
    // Tracking 2: each letter its own run, twice its advance from the last.
    let (t, r) = (run(&all, "t", [0.0, 20.0]), run(&all, "r", [0.0, 20.0]));
    assert!(t.at[0] < r.at[0] && r.at[0] - t.at[0] > 2.0, "{t:?} {r:?}");

    // The paragraph centred in its box 50 wide.
    for line in ["centred", "a longer second line"] {
        let l = run(&all, line, [25.0, 45.0]);
        assert!(near(l.at[0], 25.0) && l.h_align == 1, "{l:?}");
    }

    // The stack (MTEXT hangs from its top: baseline 57.5): 0.7 of the
    // height, about the capitals' middle (58.75).
    let small: Vec<&Run> = all.iter().filter(|r| near(r.v[1], 1.75)).collect();
    let y = |s: &str| small.iter().find(|r| r.text == s).unwrap().at[1];
    assert!(
        near(y("1"), 58.75 + 0.35) && near(y("2"), 58.75 - 0.35 - 1.75),
        "{small:?}"
    );
    assert!(!ink(&d, [0.0, 58.7], [10.0, 58.8]).is_empty(), "the bar");

    let multi = run(&all, "MULTI", [100.0, 55.0]);
    let second = run(&all, "LINE ATTR", [100.0, 55.0]);
    assert!(
        near(multi.at[0], second.at[0]) && second.at[1] < multi.at[1],
        "{multi:?} {second:?}"
    );

    let red = d
        .texts
        .chunks(TEXT_RECORD_BYTES)
        .zip(&all)
        .find(|(_, r)| r.text == "red");
    assert_eq!(&red.unwrap().0[24..28], [255, 0, 0, 255]);
}

/// A masked MTEXT covers what is under it with its colour, or the drawing's
/// background, a border of half its height around it, drawn just before
/// its text; a framed one has the frame on top.
#[test]
fn an_mtext_mask_is_under_its_text_only() {
    let d = fixture("text_mtext.dxf").tessellate(None, None);
    let tris: Vec<&[u8]> = d.fills.chunks(exav_render::dwg::FILL_BYTES).collect();
    let yellow: Vec<[f64; 2]> = tris
        .iter()
        .filter(|v| v[8..12] == [255, 255, 0, 255])
        .map(|v| [f32_at(v, 0) + d.origin[0], f32_at(v, 4) + d.origin[1]])
        .collect();
    // From the baseline (27.5) to the capitals (30), and 1.25 around.
    let b = bounds(&yellow);
    assert!(
        (b[0] + 1.25).abs() < 1e-3 && (b[1] - 26.25).abs() < 1e-3 && (b[3] - 31.25).abs() < 1e-3,
        "{b:?}"
    );
    let masked = d
        .texts
        .chunks(TEXT_RECORD_BYTES)
        .zip(runs(&d))
        .find(|(_, r)| r.text == "MASKED")
        .unwrap()
        .0;
    let mask = tris
        .iter()
        .find(|v| v[8..12] == [255, 255, 0, 255])
        .unwrap();
    assert_eq!(order(masked, 40), order(mask, 16) + 1);
    // The framed one: the background (fill flag 1) and four sides.
    assert!(tris
        .iter()
        .any(|v| v[15] == 1 && f32_at(v, 0) + d.origin[0] > 40.0));
    let frame = bounds(&ink(&d, [45.0, 25.0], [80.0, 36.0]));
    assert!(
        (frame[0] - 48.75).abs() < 1e-3 && (frame[3] - 31.25).abs() < 1e-3,
        "{frame:?}"
    );
}

/// Aligned keeps the style's width factor and scales the height to the two
/// points.
#[test]
fn aligned_text_keeps_its_width_factor() {
    let d = fixture("text_frames.dxf").tessellate(None, None);
    let all = runs(&d);
    let wide = run(&all, "WIDE", [250.0, 0.0]);
    let (u, v) = (wide.u[0].hypot(wide.u[1]), wide.v[0].hypot(wide.v[1]));
    assert!((u / v - 2.0).abs() < 1e-4, "{wide:?}");
    assert!(
        close(wide.at, [250.0, 0.0]) && wide.h_align == 0,
        "{wide:?}"
    );
}
