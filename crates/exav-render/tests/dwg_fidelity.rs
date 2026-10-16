//! What drawings show beyond their lines: widths, sheets, clipping, the
//! entities AutoCAD draws its own way. Each on a drawing of
//! `tests/fixtures/dwg/make.py` built to show it, checked against the
//! geometry the script put in.

#![cfg(feature = "dwg")]

mod cad_common;

use exav_render::dwg::{Document, Drawing, FILL_BYTES, FILL_EDGE, STROKE_BYTES};

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

/// Every stroke as world-space endpoints and its lineweight.
fn strokes(d: &Drawing) -> Vec<([f64; 4], u8)> {
    d.strokes
        .as_chunks::<STROKE_BYTES>()
        .0
        .iter()
        .map(|s| {
            let (ox, oy) = (d.origin[0], d.origin[1]);
            let attr = u32::from_le_bytes(s[20..24].try_into().unwrap());
            (
                [
                    f32_at(s, 0) + ox,
                    f32_at(s, 4) + oy,
                    f32_at(s, 8) + ox,
                    f32_at(s, 12) + oy,
                ],
                (attr >> 16) as u8,
            )
        })
        .collect()
}

/// Every fill triangle, in world coordinates.
fn triangles(d: &Drawing) -> Vec<[[f64; 2]; 3]> {
    d.fills
        .as_chunks::<{ FILL_BYTES * 3 }>()
        .0
        .iter()
        .map(|t| {
            let p = |v: usize| {
                let at = v * FILL_BYTES;
                [f32_at(t, at) + d.origin[0], f32_at(t, at + 4) + d.origin[1]]
            };
            [p(0), p(1), p(2)]
        })
        .collect()
}

fn area(tris: &[[[f64; 2]; 3]]) -> f64 {
    tris.iter()
        .map(|[a, b, c]| {
            ((b[0] - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (b[1] - a[1])).abs() / 2.0
        })
        .sum()
}

/// A polyline with width is a filled band: the 10 by 2 band, the donut's
/// annulus, the taper's triangle, each where the script drew it.
#[test]
fn wide_polylines_fill_their_bands() {
    let d = fixture("wide.dxf").tessellate(None, None);
    let tris = triangles(&d);
    let within = |x0: f64, x1: f64, y0: f64, y1: f64| -> Vec<[[f64; 2]; 3]> {
        tris.iter()
            .copied()
            .filter(|t| {
                t.iter()
                    .all(|p| p[0] >= x0 && p[0] <= x1 && p[1] >= y0 && p[1] <= y1)
            })
            .collect()
    };
    let band = area(&within(-0.1, 10.1, -1.1, 1.1));
    assert!((band - 20.0).abs() < 1e-3, "band {band}");
    let donut = area(&within(43.9, 56.1, -6.1, 6.1));
    // Radius 4, width 2: from 3 to 5.
    let annulus = std::f64::consts::PI * (25.0 - 9.0);
    assert!(
        (donut / annulus - 1.0).abs() < 0.01,
        "donut {donut} vs {annulus}"
    );
    let taper = area(&within(-0.1, 10.1, 17.9, 22.1));
    assert!((taper - 20.0).abs() < 1e-3, "taper {taper}");
    // Not drawn as lines too: the only strokes are the edges that
    // anti-alias the bands.
    assert!(
        strokes(&d).iter().all(|(_, lw)| *lw == FILL_EDGE),
        "the bands are not also drawn as lines"
    );
}

/// A layout's lineweight is a width on its sheet: the renderer needs the
/// sheet's millimetres per unit, 25.4 for one set up in inches.
#[test]
fn a_sheet_says_what_its_units_are_in_millimetres() {
    let doc = fixture("sheets.dxf");
    assert_eq!(doc.tessellate(Some("Metric"), None).sheet.mm_per_unit, 1.0);
    assert_eq!(
        doc.tessellate(Some("Imperial"), None).sheet.mm_per_unit,
        25.4
    );
    assert_eq!(doc.tessellate(None, None).sheet.mm_per_unit, 0.0);
    let json: serde_json::Value =
        serde_json::from_str(&doc.tessellate(Some("Imperial"), None).sheet_json()).unwrap();
    assert_eq!(json["mmPerUnit"], 25.4);
    // The paper: the layout's limits, an A4 sheet in landscape.
    let metric = doc.tessellate(Some("Metric"), None);
    assert_eq!(metric.sheet.paper, Some([0.0, 0.0, 297.0, 210.0]));
    assert_eq!(doc.tessellate(None, None).sheet.paper, None);
    // The 2.11 mm line is there to measure it by.
    let d = doc.tessellate(Some("Imperial"), None);
    assert!(strokes(&d).iter().any(|(_, lw)| *lw == 211));
}

/// The text records, as (string, clip region).
fn texts(d: &Drawing) -> Vec<(String, u16)> {
    d.texts
        .chunks(exav_render::dwg::TEXT_RECORD_BYTES)
        .map(|r| {
            let at = u32::from_le_bytes(r[32..36].try_into().unwrap()) as usize;
            let len = u16::from_le_bytes(r[36..38].try_into().unwrap()) as usize;
            let s = String::from_utf8_lossy(&d.text_strings[at..at + len]).into_owned();
            (s, u16::from_le_bytes(r[46..48].try_into().unwrap()))
        })
        .collect()
}

/// A text crossing a viewport's edge is kept and drawn through the
/// viewport's window as a clip region; one wholly outside is left out.
#[test]
fn a_text_crossing_a_viewports_edge_is_clipped_to_its_window() {
    let d = fixture("viewport_text.dxf").tessellate(Some("Sheet"), None);
    let t = texts(&d);
    let crossing = t
        .iter()
        .find(|(s, _)| s == "CLIPPED TEXT RUNS ON")
        .expect("kept");
    assert!(crossing.1 > 0, "{t:?}");
    assert!(!t.iter().any(|(s, _)| s == "OUTSIDE"), "{t:?}");
    // The region: the viewport's window on the sheet, 80 to 120 by 90 to 110.
    let r = regions(&d);
    assert_eq!(r.len(), 1);
    assert_eq!(bounds(&r[0]), [80.0, 90.0, 120.0, 110.0]);
}

/// Each clip region's triangle corners, in world coordinates.
fn regions(d: &Drawing) -> Vec<Vec<[f64; 2]>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= d.clips.len() {
        let count = u32::from_le_bytes(d.clips[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let corners = (0..count * 3)
            .map(|i| {
                let p = at + i * 8;
                [
                    f32_at(&d.clips, p) + d.origin[0],
                    f32_at(&d.clips, p + 4) + d.origin[1],
                ]
            })
            .collect();
        at += count * 24;
        out.push(corners);
    }
    out
}

/// Bounds of points, rounded to 1e-3.
fn bounds(ps: &[[f64; 2]]) -> [f64; 4] {
    let lo = |i: usize| ps.iter().map(|p| p[i]).fold(f64::INFINITY, f64::min);
    let hi = |i: usize| ps.iter().map(|p| p[i]).fold(f64::NEG_INFINITY, f64::max);
    [lo(0), lo(1), hi(0), hi(1)].map(|v| (v * 1000.0).round() / 1000.0)
}

/// An XCLIPped insert shows only what is inside its boundary: lines cut at
/// it, its xlines ending at it, its texts drawn through it. The boundary is
/// in block coordinates (A), or in world coordinates with the inverse insert
/// matrix (B); with clipping off (C) the block is whole.
#[test]
fn an_xclipped_insert_shows_only_what_is_inside_its_boundary() {
    for name in ["xclip.dxf", "xclip.dwg", "xclip-R2000.dwg"] {
        eprintln!("{name}");
        xclipped(name);
    }
}

fn xclipped(name: &str) {
    let d = fixture(name).tessellate(None, None);
    let all = strokes(&d);
    let near = |a: [f64; 2], b: [f64; 2]| (a[0] - b[0]).abs() < 1e-3 && (a[1] - b[1]).abs() < 1e-3;
    let has = |a: [f64; 2], b: [f64; 2]| {
        all.iter().any(|(s, _)| {
            let (p, q) = ([s[0], s[1]], [s[2], s[3]]);
            (near(p, a) && near(q, b)) || (near(p, b) && near(q, a))
        })
    };
    let around = |x0: f64, x1: f64| -> Vec<[f64; 2]> {
        all.iter()
            .filter(|(s, _)| s[0] > x0 && s[0] < x1)
            .flat_map(|(s, _)| [[s[0], s[1]], [s[2], s[3]]])
            .collect()
    };

    // A: the rectangle 80..100 by 0..20, and its frame.
    assert_eq!(bounds(&around(60.0, 120.0)), [80.0, 0.0, 100.0, 20.0]);
    assert!(has([100.0, 0.0], [80.0, 20.0]), "the diagonal, cut");
    assert!(has([90.0, 0.0], [90.0, 20.0]), "the xline, cut");
    assert!(has([80.0, 0.0], [80.0, 20.0]), "the frame");

    // B: the triangle (280,0) (300,0) (300,20).
    let b = around(260.0, 320.0);
    let inside =
        |p: &[f64; 2]| p[0] <= 300.0 + 1e-3 && p[1] >= -1e-3 && p[1] <= p[0] - 280.0 + 1e-3;
    assert!(b.iter().all(inside), "{b:?}");
    assert!(has([300.0, 0.0], [290.0, 10.0]), "the diagonal, cut");
    assert!(has([290.0, 0.0], [290.0, 10.0]), "the xline, cut");

    // C: whole.
    assert!(has([510.0, -10.0], [470.0, 30.0]), "the diagonal");
    let xline = all
        .iter()
        .find(|(s, _)| (s[0] - 490.0).abs() < 1e-3 && (s[2] - 490.0).abs() < 1e-3);
    let xline = xline.expect("the xline").0;
    assert!((xline[3] - xline[1]).abs() > 40.0, "{xline:?}");

    // The texts: A's and B's through their boundaries, C's as it is.
    let t: Vec<u16> = texts(&d).into_iter().map(|(_, clip)| clip).collect();
    assert_eq!(t.len(), 3, "{t:?}");
    let r = regions(&d);
    let mut clipped: Vec<[f64; 4]> = t
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| bounds(&r[c as usize - 1]))
        .collect();
    clipped.sort_by(|a, b| a[0].total_cmp(&b[0]));
    assert_eq!(
        clipped,
        [[80.0, 0.0, 100.0, 20.0], [280.0, 0.0, 300.0, 20.0]]
    );
    assert_eq!(t.iter().filter(|&&c| c == 0).count(), 1);
}

/// An entity's transparency holds whatever its colour: the line in its
/// layer's grey is at half opacity.
#[test]
fn transparency_holds_for_a_bylayer_colour() {
    for name in ["transparency.dxf", "transparency.dwg"] {
        let d = fixture(name).tessellate(None, None);
        let grey = d
            .strokes
            .as_chunks::<STROKE_BYTES>()
            .0
            .iter()
            .find(|s| (f32_at(s.as_slice(), 4) + d.origin[1] + 40.0).abs() < 1e-3)
            .unwrap_or_else(|| panic!("{name}: the grey line"));
        let rgba = u32::from_le_bytes(grey[16..20].try_into().unwrap());
        assert_eq!(rgba.to_le_bytes(), [65, 65, 65, 127], "{name}");
    }
}

/// What is not drawn is said by type, and the files external references
/// name; an xref shows its path where it is inserted.
#[test]
fn what_is_not_drawn_is_said() {
    for name in ["not_drawn.dxf", "not_drawn.dwg"] {
        eprintln!("{name}");
        not_drawn(name);
    }
}

fn not_drawn(name: &str) {
    let d = fixture(name).tessellate(None, None);
    let w: serde_json::Value = serde_json::from_str(&d.warnings_json()).unwrap();
    assert_eq!(w["unknownEntities"], 3);
    assert_eq!(
        w["notDrawn"],
        serde_json::json!({"3DSOLID": 2, "REGION": 1})
    );
    assert_eq!(w["externalReferences"], 3);
    assert_eq!(
        w["externalFiles"],
        serde_json::json!(["photo.png", "walls.dwg"])
    );
    // In the STANDARD style's stroke font, 2.5 high: a row of strokes from
    // each insertion point.
    let all = strokes(&d);
    for x in [10.0, 50.0] {
        let glyphs: Vec<[f64; 4]> = all
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| [s[0], s[2]].iter().all(|v| (x - 0.1..x + 30.0).contains(v)))
            .filter(|s| [s[1], s[3]].iter().all(|v| (9.9..13.0).contains(v)))
            .collect();
        assert!(glyphs.len() > 20, "at {x}: {glyphs:?}");
    }
}

/// A pattern too dense to draw line by line is its region in a half tone,
/// not some lines and a gap; one spaced under a unit still records its
/// spacing, so the renderer fades its lines once they crowd a pixel.
#[test]
fn dense_hatches_keep_their_tone() {
    let d = fixture("dense_hatch.dxf").tessellate(None, None);
    let red: Vec<[[f64; 2]; 3]> = triangles(&d)
        .into_iter()
        .zip(d.fills.as_chunks::<{ FILL_BYTES * 3 }>().0)
        .filter(|(_, t)| t[8..12] == [255, 0, 0, 128])
        .map(|(t, _)| t)
        .collect();
    assert!((area(&red) - 1_000_000.0).abs() < 1.0, "{}", area(&red));
    assert!(
        strokes(&d).iter().all(|(s, _)| s[0] >= 1999.0),
        "no red lines"
    );
    let flags: Vec<u8> = d
        .strokes
        .as_chunks::<STROKE_BYTES>()
        .0
        .iter()
        .map(|s| s[23])
        .collect();
    assert!(
        !flags.is_empty() && flags.iter().all(|f| f & 0x7F != 0),
        "{flags:?}"
    );
}

/// The strokes inside a box, as segments.
fn segments_in(d: &Drawing, min: [f64; 2], max: [f64; 2]) -> Vec<[f64; 4]> {
    let inside = |x: f64, y: f64| x >= min[0] && x <= max[0] && y >= min[1] && y <= max[1];
    strokes(d)
        .into_iter()
        .map(|(s, _)| s)
        .filter(|s| inside(s[0], s[1]) && inside(s[2], s[3]))
        .collect()
}

/// What used to be left out or drawn plain: a 3DFACE's hidden edges, point
/// styles, meshes, feature control frames, leader arrows.
#[test]
fn faces_points_meshes_tolerances_and_arrows_are_drawn() {
    for name in ["gaps.dxf", "gaps.dwg"] {
        eprintln!("{name}");
        gaps(name);
    }
}

fn gaps(name: &str) {
    let d = fixture(name).tessellate(None, None);
    let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
    let has = |segs: &[[f64; 4]], s: [f64; 4]| {
        segs.iter().any(|t| {
            (near(t[0], s[0]) && near(t[1], s[1]) && near(t[2], s[2]) && near(t[3], s[3]))
                || (near(t[0], s[2]) && near(t[1], s[3]) && near(t[2], s[0]) && near(t[3], s[1]))
        })
    };

    // The face: its second and fourth edges only.
    let face = segments_in(&d, [-1.0, -1.0], [11.0, 11.0]);
    assert_eq!(face.len(), 2, "{face:?}");
    assert!(has(&face, [10.0, 0.0, 10.0, 10.0]) && has(&face, [0.0, 10.0, 0.0, 0.0]));

    // The point: a cross and a circle, 2 across.
    let point = segments_in(&d, [98.0, -2.0], [102.0, 2.0]);
    assert!(has(&point, [99.0, -1.0, 101.0, 1.0]) && has(&point, [99.0, 1.0, 101.0, -1.0]));
    assert!(point.len() > 10, "the circle");

    // Each cube's twelve edges (seen from above they overlap in pairs and
    // fours, which are still twelve segments), the grid's twelve.
    for x in [200.0, 400.0] {
        let cube = segments_in(&d, [x - 1.0, -1.0], [x + 2.0, 2.0]);
        assert_eq!(cube.len(), 12, "at {x}: {cube:?}");
    }
    assert_eq!(segments_in(&d, [299.0, -1.0], [303.0, 3.0]).len(), 12);

    // The frame: three boxes 3 high (2 and a gap of 0.5 each side) about
    // y 0 from x 500.
    let frame = segments_in(&d, [499.0, -2.0], [540.0, 2.0]);
    let tops = frame
        .iter()
        .filter(|s| near(s[1], 1.5) && near(s[3], 1.5))
        .count();
    assert_eq!(tops, 3, "{frame:?}");
    assert!(frame.iter().any(|s| near(s[0], 500.0) && near(s[2], 500.0)));

    // The leader's dot about its tip, not a triangle down the leader.
    let tris = triangles(&d);
    let dot: Vec<[f64; 2]> = tris
        .iter()
        .flatten()
        .copied()
        .filter(|p| (p[0] - 600.0).abs() < 3.0 && p[1].abs() < 3.0)
        .collect();
    let lo = |i: usize| dot.iter().map(|p| p[i]).fold(f64::INFINITY, f64::min);
    let hi = |i: usize| dot.iter().map(|p| p[i]).fold(f64::NEG_INFINITY, f64::max);
    assert!(
        !dot.is_empty() && near(lo(0) + hi(0), 1200.0) && near(lo(1) + hi(1), 0.0),
        "{dot:?}"
    );
    // The multileader's arrow, 3 long, at its tip.
    let arrow: Vec<[f64; 2]> = tris
        .iter()
        .flatten()
        .copied()
        .filter(|p| (p[0] - 701.5).abs() < 2.0 && p[1].abs() < 2.0)
        .collect();
    assert!(
        arrow.iter().any(|p| near(p[0], 700.0) && near(p[1], 0.0)),
        "{arrow:?}"
    );
}

/// A line left at the origin of a plan in national grid coordinates no
/// longer pulls the f32 origin and the fitted view halfway to it: the plan
/// keeps its precision (a circle 0.5 across stays one) and fills the view;
/// the stray is still drawn.
#[test]
fn a_stray_far_off_does_not_cost_the_drawing_its_precision() {
    let d = fixture("stray.dxf").tessellate(None, None);
    let (x0, y0) = (38_985_257.0, 5_800_000.0);
    assert!(
        (d.origin[0] - x0).abs() < 200.0 && (d.origin[1] - y0).abs() < 200.0,
        "{:?}",
        d.origin
    );
    let e = d.extents;
    assert!(e[2] - e[0] < 200.0 && e[3] - e[1] < 200.0, "{e:?}");
    let centre = [x0 + 50.25, y0 + 50.25];
    let ring: Vec<f64> = strokes(&d)
        .iter()
        .flat_map(|(s, _)| [[s[0], s[1]], [s[2], s[3]]])
        .map(|p| (p[0] - centre[0]).hypot(p[1] - centre[1]))
        .filter(|r| (*r - 0.5).abs() < 0.2)
        .collect();
    // Four quarter arcs, their eight ends on the circle.
    assert!(
        ring.len() == 8 && ring.iter().all(|r| (r - 0.5).abs() < 1e-3),
        "{ring:?}"
    );
    // The stray keeps a f32's precision 39 million units off: a few units.
    assert!(
        strokes(&d)
            .iter()
            .any(|(s, _)| s[0].abs() < 8.0 && s[1].abs() < 8.0),
        "the stray"
    );
}

/// PLINEGEN carries a polyline's dashes on across its vertices; without
/// it, each segment starts its pattern with a dash.
#[test]
fn plinegen_says_whether_dashes_run_on_across_vertices() {
    for name in ["plinegen.dxf", "plinegen.dwg"] {
        let d = fixture(name).tessellate(None, None);
        // The lowest dash up the second segment, from its corner.
        let first_up = |y: f64| {
            strokes(&d)
                .iter()
                .map(|(s, _)| *s)
                .filter(|s| {
                    (s[0] - 10.75).abs() < 1e-3
                        && (s[2] - 10.75).abs() < 1e-3
                        && s[1].min(s[3]) >= y - 1e-3
                })
                .map(|s| s[1].min(s[3]) - y)
                .fold(f64::INFINITY, f64::min)
        };
        assert!(
            (first_up(0.0) - 0.25).abs() < 1e-3,
            "{name} carried on: {}",
            first_up(0.0)
        );
        assert!(
            first_up(20.0).abs() < 1e-3,
            "{name} afresh: {}",
            first_up(20.0)
        );
    }
}

/// AutoCAD's complex linetypes stamp ltypeshp.shx's shapes, and their text,
/// at the end of the element carrying them, shifted by its offset.
#[test]
fn complex_linetypes_stamp_their_shapes_and_text() {
    for name in ["complex_linetypes.dxf", "complex_linetypes.dwg"] {
        eprintln!("{name}");
        complex_linetypes(name);
    }
}

fn complex_linetypes(name: &str) {
    let d = fixture(name).tessellate(None, None);
    let all: Vec<[f64; 4]> = strokes(&d).into_iter().map(|(s, _)| s).collect();
    let near = |a: f64, b: f64| (a - b).abs() < 1e-4;
    let has = |a: [f64; 2], b: [f64; 2]| {
        all.iter().any(|t| {
            (near(t[0], a[0]) && near(t[1], a[1]) && near(t[2], b[0]) && near(t[3], b[1]))
                || (near(t[0], b[0]) && near(t[1], b[1]) && near(t[2], a[0]) && near(t[3], a[1]))
        })
    };

    // FENCELINE2: a square 0.2 across over each gap of 0.2, at x 0.25 and 1.7.
    for x in [0.25, 1.7] {
        assert!(
            has([x, -0.1], [x + 0.2, -0.1]) && has([x + 0.2, -0.1], [x + 0.2, 0.1]),
            "box at {x}"
        );
        assert!(
            has([x + 0.2, 0.1], [x, 0.1]) && has([x, 0.1], [x, -0.1]),
            "box at {x}"
        );
    }
    assert!(!has([3.15, -0.1], [3.35, -0.1]), "none past the line's end");

    // FENCELINE1: a circle 0.2 across in the gap, as four quarter arcs.
    for x in [0.35, 1.8] {
        let ends = all
            .iter()
            .filter(|t| {
                [[t[0], t[1]], [t[2], t[3]]]
                    .iter()
                    .all(|p| near((p[0] - x).hypot(p[1] - 10.0), 0.1))
            })
            .count();
        assert_eq!(ends, 4, "circle at {x}");
    }

    // TRACKS: a tie 0.5 long every 0.3, from 0.15.
    let ties = all
        .iter()
        .filter(|t| near(t[0], t[2]) && near(t[1].min(t[3]), 19.75) && near(t[1].max(t[3]), 20.25));
    let mut xs: Vec<f64> = ties.map(|t| t[0]).collect();
    xs.sort_by(f64::total_cmp);
    assert_eq!(xs.len(), 10, "{xs:?}");
    assert!(near(xs[0], 0.15) && near(xs[9], 2.85), "{xs:?}");

    // ZIGZAG: a tooth 0.4 wide up, then one down, turned half a turn.
    assert!(
        has([0.0001, 30.0], [0.2001, 30.2]) && has([0.2001, 30.2], [0.4001, 30.0]),
        "up"
    );
    assert!(
        has([0.8001, 30.0], [0.6001, 29.8]) && has([0.6001, 29.8], [0.4001, 30.0]),
        "down"
    );

    // BATTING: an arch on its two legs above the line, then one below.
    assert!(
        has([0.0001, 40.0], [-0.0999, 40.2]) && has([0.3001, 40.2], [0.2001, 40.0]),
        "above"
    );
    assert!(
        has([0.4001, 40.0], [0.5001, 39.8]) && has([0.1001, 39.8], [0.2001, 40.0]),
        "below"
    );

    // GAS_LINE: its text 0.1 back from the end of the gap after each dash,
    // 0.05 below the line.
    let gas: Vec<[f64; 2]> = d
        .texts
        .chunks(exav_render::dwg::TEXT_RECORD_BYTES)
        .map(|r| [f32_at(r, 0) + d.origin[0], f32_at(r, 4) + d.origin[1]])
        .collect();
    assert!(
        gas.iter().any(|p| near(p[0], 0.6) && near(p[1], 49.95)),
        "{gas:?}"
    );
    assert!(
        gas.iter().any(|p| near(p[0], 1.55) && near(p[1], 49.95)),
        "{gas:?}"
    );
}

/// A dimension saved without its block is drawn from its definition points
/// and style: extension and dimension lines, arrowheads or ticks, arcs, and
/// its measurement written as the style says.
#[test]
fn a_dimension_without_its_block_is_drawn_from_its_definition() {
    let d = fixture("dimensions.dxf").tessellate(None, None);
    let w: serde_json::Value = serde_json::from_str(&d.warnings_json()).unwrap();
    assert_eq!(w["missingBlocks"], 0);
    let all: Vec<[f64; 4]> = strokes(&d).into_iter().map(|(s, _)| s).collect();
    let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
    let has = |a: [f64; 2], b: [f64; 2]| {
        all.iter().any(|t| {
            (near(t[0], a[0]) && near(t[1], a[1]) && near(t[2], b[0]) && near(t[3], b[1]))
                || (near(t[0], b[0]) && near(t[1], b[1]) && near(t[2], a[0]) && near(t[3], a[1]))
        })
    };

    // The texts: two places, trailing zeros off, a comma; R and the
    // diameter sign before a radius and a diameter; halves rounded up.
    let mut t: Vec<String> = texts(&d).into_iter().map(|(s, _)| s).collect();
    t.sort();
    assert_eq!(
        t,
        [
            "100",
            "101",
            "112,25 mm",
            "45,00°",
            "50",
            "800",
            "90,00°",
            "R30",
            "Ø50"
        ]
    );

    // Linear: extension lines from 0.625 off the points to 1.25 past the
    // dimension line on y 20, which is whole, its text above it.
    assert!(has([0.0, 0.625], [0.0, 21.25]) && has([100.0, 0.625], [100.0, 21.25]));
    assert!(has([0.0, 20.0], [100.0, 20.0]));
    let tips = |x: f64, y: f64| {
        triangles(&d)
            .iter()
            .flatten()
            .any(|p| near(p[0], x) && near(p[1], y))
    };
    assert!(tips(0.0, 20.0) && tips(100.0, 20.0), "arrowheads");

    // Ticks: no arrowheads, 45 degree strokes 1.5 across, the line run 1.25
    // past them and broken about its text.
    assert!(!tips(0.0, -30.0));
    assert!(has([-0.75, -30.75], [0.75, -29.25]) && has([99.75, -30.75], [101.25, -29.25]));
    let line: Vec<&[f64; 4]> = all
        .iter()
        .filter(|s| near(s[1], -30.0) && near(s[3], -30.0))
        .collect();
    assert_eq!(line.len(), 2, "{line:?}");
    let ends: Vec<f64> = line.iter().flat_map(|s| [s[0], s[2]]).collect();
    assert!(
        ends.iter().any(|x| near(*x, -1.25)) && ends.iter().any(|x| near(*x, 101.75)),
        "{ends:?}"
    );
    assert!(
        ends.iter().all(|x| (x - 50.25).abs() > 2.0),
        "the gap about the text: {ends:?}"
    );

    // Angles: an arc about the vertex through the point given, from leg to
    // leg: a quarter turn, then an eighth.
    let r = 800f64.sqrt();
    assert!(has([600.0 + r, 0.0], [600.0, r]), "90 degrees");
    let r = 725f64.sqrt();
    let h = std::f64::consts::FRAC_1_SQRT_2 * r;
    assert!(has([700.0 + r, 0.0], [700.0 + h, h]), "45 degrees");

    // The ordinate's line from 0.625 above the feature to 1.25 past its end.
    assert!(has([800.0, 10.625], [800.0, 41.25]));
}

/// `$LWDISPLAY` says whether the drawing is shown with its lineweights.
#[test]
fn a_drawing_says_whether_its_lineweights_are_shown() {
    assert!(
        fixture("sheets.dxf")
            .tessellate(None, None)
            .sheet
            .lineweights
    );
    assert!(!fixture("wide.dxf").tessellate(None, None).sheet.lineweights);
}
