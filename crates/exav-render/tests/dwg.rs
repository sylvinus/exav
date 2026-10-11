//! DWG and DXF end to end: drawings written by ezdxf and converted to DWG by
//! the ODA File Converter (`tests/fixtures/dwg/make.py`), read, tessellated,
//! and checked against the geometry that was put in.
//!
//! Nothing here is a third-party file. A corpus of real drawings can be run
//! through the same checks with `EXAV_DEBUG_DWG_CORPUS=<dir>`.

#![cfg(feature = "dwg")]

mod cad_common;

use exav_render::dwg::{Document, Drawing, ParseError, FILL_BYTES, STROKE_BYTES};

/// A drawing of `tests/fixtures/dwg`, by file name without `.gz`.
fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dwg")
        .join(format!("{name}.gz"));
    let gz = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    cad_common::gunzip(&gz)
}

/// Every stroke as world-space endpoints and layer name.
fn strokes(d: &Drawing) -> Vec<([f64; 4], String)> {
    d.strokes
        .as_chunks::<STROKE_BYTES>()
        .0
        .iter()
        .map(|s| {
            let f = |i: usize| f64::from(f32::from_le_bytes(s[i..i + 4].try_into().unwrap()));
            let attr = u32::from_le_bytes(s[20..24].try_into().unwrap());
            let layer = d.layers[(attr & 0xffff) as usize].name.clone();
            let (ox, oy) = (d.origin[0], d.origin[1]);
            ([f(0) + ox, f(4) + oy, f(8) + ox, f(12) + oy], layer)
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
                let f = |i: usize| {
                    let at = v * FILL_BYTES + i;
                    f64::from(f32::from_le_bytes(t[at..at + 4].try_into().unwrap()))
                };
                [f(0) + d.origin[0], f(4) + d.origin[1]]
            };
            [p(0), p(1), p(2)]
        })
        .collect()
}

#[test]
fn a_drawing_comes_back_as_it_was_written_in_dwg_and_dxf() {
    for what in ["plan.dwg", "plan-R2000.dwg", "plan.dxf"] {
        let parsed = Document::parse(&fixture(what)).unwrap_or_else(|e| panic!("{what}: {e}"));
        let layouts = parsed.layouts();
        assert!(layouts[0].is_model, "{what}: model space first");
        assert!(
            layouts.iter().any(|l| l.name == "Sheet A" && !l.is_model),
            "{what}"
        );

        let d = parsed.tessellate(None, Some([255, 255, 255]));
        assert_eq!(d.layout, "", "{what}: model space");
        let walls = d.layers.iter().find(|l| l.name == "WALLS").expect("WALLS");
        // Index 1 is red; packed little-endian RGBA.
        assert_eq!(walls.rgba, 0xff00_00ff, "{what}");
        let notes = d.layers.iter().find(|l| l.name == "NOTES").expect("NOTES");
        assert_eq!(notes.rgba, 0xffff_0000, "{what}: index 5 is blue");

        let s = strokes(&d);
        let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
        assert!(
            s.iter().any(|(p, l)| l == "WALLS"
                && near(p[0], 0.0)
                && near(p[1], 0.0)
                && near(p[2], 100.0)
                && near(p[3], 0.0)),
            "{what}: the wall is one stroke from (0,0) to (100,0)"
        );
        // The column, flattened: every point of its strokes on the circle.
        let on_circle: Vec<_> = s
            .iter()
            .filter(|(p, l)| l == "WALLS" && !(near(p[1], 0.0) && near(p[3], 0.0)))
            .collect();
        assert!(
            on_circle.len() >= 16,
            "{what}: {} column strokes",
            on_circle.len()
        );
        for (p, _) in &on_circle {
            for (x, y) in [(p[0], p[1]), (p[2], p[3])] {
                let r = ((x - 50.0).powi(2) + (y - 50.0).powi(2)).sqrt();
                assert!(
                    (r - 25.0).abs() < 1e-2,
                    "{what}: ({x}, {y}) is {r} from the centre"
                );
            }
        }
        // Extents: the wall from x 0 to 100, the column up to y 75.
        let ext = [
            d.extents[0] as f64 + d.origin[0],
            d.extents[1] as f64 + d.origin[1],
            d.extents[2] as f64 + d.origin[0],
            d.extents[3] as f64 + d.origin[1],
        ];
        assert!(
            near(ext[0], 0.0) && near(ext[2], 100.0) && ext[3] > 74.9 && ext[3] < 75.1,
            "{what}: {ext:?}"
        );

        // The label: an outline-face run carrying its characters, or stroke
        // glyphs, depending on what the style's font resolves to.
        let text = String::from_utf8_lossy(&d.text_strings).into_owned();
        assert!(
            text.contains("HELLO") || d.warnings.stroke_glyphs >= 5,
            "{what}: text {text:?}, {} stroke glyphs",
            d.warnings.stroke_glyphs
        );
        assert_eq!(d.warnings.unknown_entities, 0, "{what}");
    }
}

/// A layout that does not exist draws model space and says so, rather than
/// failing: the host keeps showing the drawing.
/// A HATCH edge on an ellipse runs between the angles DXF gives (50, 51),
/// which are not the ellipse's parameters there: the edge from 30 to 120
/// degrees of an ellipse 10 by 5 ends at (6.55, 3.78) and (-2.77, 4.80),
/// not at the parameters' (8.66, 2.5) and (-5, 4.33). The same in the DXF
/// ezdxf wrote and in the converter's DWG of it, which stores parameters
/// (`tests/fixtures/cad/make.py`, source c7).
#[test]
fn a_hatch_edge_on_an_ellipse_spans_its_angles() {
    let cad = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cad");
    for path in ["src/c7.dxf.gz", "dwg/R2018/c7.dwg.gz"] {
        let bytes = cad_common::gunzip(&std::fs::read(cad.join(path)).expect("fixture"));
        let doc = Document::parse(&bytes).expect("parses");
        let d = doc.tessellate(None, None);
        let points: Vec<[f64; 2]> = triangles(&d).into_iter().flatten().collect();
        assert!(!points.is_empty(), "{path}: no fill");
        let lo = |i: usize| points.iter().map(|p| p[i]).fold(f64::INFINITY, f64::min);
        let hi = |i: usize| {
            points
                .iter()
                .map(|p| p[i])
                .fold(f64::NEG_INFINITY, f64::max)
        };
        let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
        assert!(
            near(lo(0), -2.7735) && near(hi(0), 6.5465) && near(lo(1), 3.7796) && near(hi(1), 5.0),
            "{path}: fill box {} {} {} {}",
            lo(0),
            lo(1),
            hi(0),
            hi(1)
        );
    }
}

#[test]
fn an_unknown_layout_draws_model_space() {
    let parsed = Document::parse(&fixture("plan.dwg")).unwrap();
    let d = parsed.tessellate(Some("No such sheet"), None);
    assert_eq!(d.layout, "");
    assert!(d.stroke_count() > 0);
    let sheet = parsed.tessellate(Some("Sheet A"), None);
    assert_eq!(sheet.layout, "Sheet A");
}

/// Layer and layout names are file data; the JSON stays JSON whatever they
/// hold. (A newline cannot be in a DXF name: `json_string`'s unit test has
/// it.)
#[test]
fn hostile_names_stay_valid_json() {
    let hostile = "Q\"\\\t\u{1}";
    let parsed = Document::parse(&fixture("hostile.dxf")).unwrap();
    let d = parsed.tessellate(None, None);
    for json in [d.layers_json(), d.warnings_json(), parsed.layouts_json()] {
        let v: serde_json::Value =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}: {json}"));
        assert!(v.is_array() || v.is_object());
    }
    // The JSON says what the table holds, name for name.
    let layers: serde_json::Value = serde_json::from_str(&d.layers_json()).unwrap();
    let names: Vec<&str> = layers
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["name"].as_str().unwrap())
        .collect();
    let table: Vec<&str> = d.layers.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(names, table);
    assert!(table.contains(&hostile), "{table:?}");
    assert!(strokes(&d).iter().any(|(_, l)| l == hostile));
}

/// A DXF a text editor saved with UTF-8's byte order mark is the same drawing.
#[test]
fn a_dxf_with_a_byte_order_mark_is_the_same_drawing() {
    let dxf = fixture("plan.dxf");
    let mut marked = b"\xEF\xBB\xBF".to_vec();
    marked.extend_from_slice(&dxf);
    let plain = Document::parse(&dxf).unwrap().tessellate(None, None);
    let bom = Document::parse(&marked)
        .expect("a DXF behind a BOM")
        .tessellate(None, None);
    assert_eq!(strokes(&bom), strokes(&plain));
}

/// A host's budget stops the scene where it says, between entities, and
/// counts what it left out; the default draws the same file whole.
#[test]
fn a_budget_set_by_the_host_cuts_the_drawing_there() {
    let parsed = Document::parse(&fixture("lines200.dxf")).unwrap();

    let whole = parsed.tessellate(None, None);
    assert_eq!(whole.stroke_count(), 200);
    assert_eq!(whole.warnings.scene_truncated, 0);

    let cut = parsed.tessellate_within(None, None, 50);
    assert_eq!(cut.stroke_count(), 50);
    assert_eq!(cut.warnings.scene_truncated, 150);
    // What is kept is the first fifty lines in the file's order.
    let mut ys: Vec<f64> = strokes(&cut).iter().map(|(s, _)| s[1]).collect();
    ys.sort_by(f64::total_cmp);
    assert_eq!(ys, (0..50).map(f64::from).collect::<Vec<_>>());
}

/// Not a drawing: an error, not a guess.
#[test]
fn a_file_that_is_neither_is_refused() {
    assert!(matches!(
        Document::parse(b"%PDF-1.7 ..."),
        Err(ParseError(_))
    ));
    assert!(Document::parse(b"").is_err());
}

/// Each stroke's flags byte, by the name of its layer.
fn stroke_flags(d: &Drawing, layer: &str) -> Vec<u8> {
    d.strokes
        .as_chunks::<STROKE_BYTES>()
        .0
        .iter()
        .map(|s| u32::from_le_bytes(s[20..24].try_into().unwrap()))
        .filter(|attr| d.layers[(attr & 0xffff) as usize].name == layer)
        .map(|attr| (attr >> 24) as u8)
        .collect()
}

/// Colour 7 is white on a dark ground and black on a light one, which the
/// renderer does from a flag on each stroke: a pattern hatch in colour 7 must
/// carry it as a line in colour 7 does, or it is drawn white on white.
#[test]
fn a_pattern_hatch_in_colour_7_carries_the_contrast_flag_a_line_does() {
    for what in ["hatch7.dwg", "hatch7.dxf"] {
        let d = Document::parse(&fixture(what))
            .unwrap()
            .tessellate(None, Some([255, 255, 255]));
        let line = stroke_flags(&d, "LINES");
        let hatch = stroke_flags(&d, "HATCHES");
        assert_eq!(line.len(), 1, "{what}");
        assert!(hatch.len() > 20, "{what}: {} hatch strokes", hatch.len());
        let contrast = line[0] & 0x80;
        assert_ne!(contrast, 0, "{what}: a colour-7 line has the flag");
        assert!(
            hatch.iter().all(|f| f & 0x80 == contrast),
            "{what}: {hatch:x?}"
        );
    }
}

/// An insert's attributes (a title block's fields, a door's number) are
/// drawn with it: they are not in the block, they hang off the insert.
#[test]
fn an_inserts_attributes_are_drawn() {
    for what in ["attribs.dwg", "attribs-R2000.dwg", "attribs.dxf"] {
        // A TrueType style, so the text comes back as text runs: stroke-font
        // text is tessellated into strokes.
        let d = Document::parse(&fixture(what))
            .unwrap()
            .tessellate(None, None);
        let strings = String::from_utf8_lossy(&d.text_strings);
        assert!(
            strings.contains("D-104"),
            "{what}: the attribute is missing from {strings:?}"
        );
        assert!(
            !strings.contains("SECRET"),
            "{what}: an invisible attribute is drawn"
        );
        // Outside ASCII, in every version: a 2000 DWG's strings are in its
        // code page.
        assert!(strings.contains("Tür 25°"), "{what}: {strings:?}");
    }
}

/// A LEADER's arrowhead is as long as its dimension style says (DIMASZ
/// times DIMSCALE, here 2.5 by 2), and drawn when the leader carries no text
/// height to go by.
#[test]
fn a_leader_arrowhead_takes_its_size_from_the_dimension_style() {
    let d = Document::parse(&fixture("leader.dxf"))
        .unwrap()
        .tessellate(None, None);
    let t = triangles(&d);
    assert_eq!(t.len(), 1, "one arrowhead: {t:?}");
    let [tip, b, c] = t[0];
    let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
    assert!(near(tip[0], 0.0) && near(tip[1], 0.0), "tip {tip:?}");
    // Back along the first segment, which runs along +X.
    let base = [(b[0] + c[0]) / 2.0, (b[1] + c[1]) / 2.0];
    assert!(near(base[0], 5.0) && near(base[1], 0.0), "base {base:?}");
    assert!(near((b[1] - c[1]).abs(), 5.0 / 3.0), "width {b:?} {c:?}");
}

/// Every layout draws model space through its viewport, the current one
/// and the others. DWG keeps no viewport status, only an off flag, and a
/// reader that took a missing status for "off" left every layout but the
/// current one empty.
#[test]
fn every_layout_draws_through_its_viewport() {
    for what in ["layouts.dwg", "layouts.dxf"] {
        let parsed = Document::parse(&fixture(what)).unwrap();
        for name in ["A", "B"] {
            let d = parsed.tessellate(Some(name), None);
            assert_eq!(d.layout, name, "{what}");
            // The model's line from (0,0) to (100,0), seen through a 40-unit
            // view centred on (50,0) in a 40 by 80 window at (50,50): one to
            // one, clipped to the window's 80-unit width, at y 50.
            let s = strokes(&d);
            let near = |a: f64, b: f64| (a - b).abs() < 1e-3;
            assert!(
                s.iter().any(|(p, _)| near(p[1], 50.0)
                    && near(p[3], 50.0)
                    && near((p[2] - p[0]).abs(), 80.0)),
                "{what} {name}: {s:?}"
            );
        }
    }
}

/// The panics while `f` runs, with where each happened, caught or not: in
/// the browser any panic traps the wasm instance and loses the drawing.
///
/// The hook is process-wide and sees every thread's panics: two callers
/// would see each other's, so they take turns.
fn panics_in(f: impl FnOnce()) -> Vec<String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, Once};
    static TURN: Mutex<()> = Mutex::new(());
    static COUNTING: AtomicBool = AtomicBool::new(false);
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if COUNTING.load(Ordering::SeqCst) {
                SEEN.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(info.to_string());
            } else {
                default(info);
            }
        }));
    });
    let _turn = TURN.lock().unwrap_or_else(|e| e.into_inner());
    COUNTING.store(true, Ordering::SeqCst);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    COUNTING.store(false, Ordering::SeqCst);
    std::mem::take(&mut *SEEN.lock().unwrap_or_else(|e| e.into_inner()))
}

fn read_every_layout(bytes: &[u8]) {
    if let Ok(d) = Document::parse(bytes) {
        for l in d.layouts() {
            for ground in [[255, 255, 255], [33, 40, 48]] {
                d.tessellate(Some(&l.name), Some(ground));
            }
        }
    }
}

fn sites(panics: &[String]) -> String {
    let mut sites: Vec<&str> = panics
        .iter()
        .map(|p| p.lines().next().unwrap_or(""))
        .collect();
    sites.sort_unstable();
    sites.dedup();
    sites.join("\n")
}

/// `bytes` cut short and bit-flipped fail cleanly, without a panic, caught
/// or not.
fn damaged_copies_fail_without_panicking(bytes: &[u8]) {
    let mut cases = 0;
    let panics = panics_in(|| {
        for percent in [1, 2, 5, 10, 25, 50, 75, 90, 99] {
            read_every_layout(&bytes[..bytes.len() * percent / 100]);
            cases += 1;
        }
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..200 {
            let mut b = bytes.to_vec();
            for _ in 0..4 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let i = (state as usize) % b.len();
                b[i] ^= 1 << (state >> 61);
            }
            read_every_layout(&b);
            cases += 1;
        }
    });
    assert!(
        panics.is_empty(),
        "{} panics over {cases} damaged files, at:\n{}",
        panics.len(),
        sites(&panics)
    );
}

#[test]
fn a_damaged_dxf_fails_without_panicking() {
    damaged_copies_fail_without_panicking(&fixture("plan.dxf"));
}

/// Its 16th copy (a bit flip) made the former DWG reader ask for 2 TiB and
/// abort.
#[test]
fn a_damaged_dwg_fails_without_panicking() {
    damaged_copies_fail_without_panicking(&fixture("plan.dwg"));
}

/// The most memory this process has held, in bytes (Linux; None elsewhere).
fn peak_resident() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))?
        .trim()
        .trim_end_matches("kB")
        .trim();
    kb.parse::<u64>().ok().map(|kb| kb * 1024)
}

/// What the `drawing` fuzzer found, in `tests/fixtures/fuzz/`: each one parses
/// or is refused, and every layout tessellates on both grounds, in seconds,
/// without a panic, and in a few hundred megabytes. They are mutations of the
/// demo's generated `plan.dwg` and `plan.dxf`.
#[test]
fn the_fuzzers_findings_fail_quickly_and_cleanly() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fuzz");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    assert!(!files.is_empty());
    for f in files {
        let bytes = std::fs::read(&f).unwrap();
        let before = peak_resident();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(panics_in(|| read_every_layout(&bytes)));
        });
        // Each takes milliseconds; one that loops on a damaged count takes
        // many seconds even where it ends.
        let panics = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{} did not finish within 5 s", f.display()));
        assert!(panics.is_empty(), "{}: {}", f.display(), sites(&panics));
        if let (Some(before), Some(after)) = (before, peak_resident()) {
            let grew = after.saturating_sub(before);
            assert!(
                grew < 512 << 20,
                "{} took the process {} MiB higher",
                f.display(),
                grew >> 20
            );
        }
    }
}

/// `EXAV_DEBUG_DWG_CORPUS=<dir>`: every `.dwg` and `.dxf` in it parses or fails
/// cleanly, and tessellates.
#[test]
fn a_corpus_of_real_drawings_reads_cleanly() {
    let Some(dir) = std::env::var_os("EXAV_DEBUG_DWG_CORPUS") else {
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("dwg") || x.eq_ignore_ascii_case("dxf"))
        })
        .collect();
    files.sort();
    let (mut read, mut refused) = (0, 0);
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        match Document::parse(&bytes) {
            Ok(d) => {
                for l in d.layouts() {
                    d.tessellate(Some(&l.name), None);
                }
                read += 1;
            }
            Err(e) => {
                eprintln!("{}: {e}", f.display());
                refused += 1;
            }
        }
    }
    eprintln!("{read} read, {refused} refused, of {}", files.len());
}
