//! The drawings `tests/fixtures/cad/make.py` writes with ezdxf, as the ODA
//! File Converter saved them as DWG of R13, R14, 2000, 2004, 2007, 2010, 2013
//! and 2018 (`dwg/<VERSION>/`), read with the DWG reader and checked against the
//! values the script put in (`expected.json`), and against the DXF reader's
//! reading of the converter's DXF of the same source and version, by
//! handle. Then damaged copies of them.

#[path = "cad_common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use common::compare::{entity_diffs, object_differences};
use common::{entity_by_handle, expected, resolve, same, same_name};
use exav_render::cad::{read_dwg, read_dwg_with, Error, Limits, WarningKind};
use serde_json::Value;

const VERSIONS: [&str; 8] = [
    "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
];
/// The versions the converter also wrote DXF of (`ascii/<VERSION>/`).
const WITH_DXF: [&str; 6] = ["R2000", "R2004", "R2007", "R2010", "R2013", "R2018"];

fn before_2000(version: &str) -> bool {
    matches!(version, "R13" | "R14")
}
const SOURCES: [&str; 6] = ["all", "cp1251", "dwgcases", "entities", "objects", "c7"];
/// The sources the converter also wrote DXF of (`dwgcases`, `entities` and
/// `objects` are DWG only).
const DXF_SOURCES: [&str; 2] = ["all", "cp1251"];

/// Types R13 has no form of: the converter writes an LWPOLYLINE as a
/// POLYLINE, a HATCH or MULTILEADER as an INSERT of a block it makes.
const NOT_IN_R13: [&str; 3] = ["LWPOLYLINE", "HATCH", "MULTILEADER"];

fn dwg(version: &str, source: &str) -> Vec<u8> {
    let path = format!("dwg/{version}/{source}.dwg");
    common::fixture(&path).unwrap_or_else(|| panic!("{path} missing"))
}

fn dump(bytes: &[u8]) -> Value {
    let d = read_dwg(bytes).expect("a fixture reads");
    assert!(d.warnings.is_empty(), "{:?}", d.warnings);
    serde_json::from_str(&exav_render::cad::to_json(&d)).expect("JSON")
}

/// Fields a version cannot hold, which the converter drops or
/// approximates: true colours and entity transparency before 2004 (a
/// layer's is in its extended data), lineweights and `$INSUNITS` before
/// 2000; an MTEXT background before 2004; a multiline attribute before
/// 2018 (the converter writes one attribute per line, `NOTE_001`...); a
/// viewport's off flag (so its status and number) and clip boundary before
/// 2000; a dictionary's cloning flag before 2000 (spec 20.4.44). And what
/// no version holds: a SHAPE's name.
fn version_drops(version: &str, ty: &str, field: &str, value: &Value) -> bool {
    let before_2004 = before_2000(version) || version == "R2000";
    match (ty, field) {
        (_, "transparency") => before_2004,
        (_, "color") => before_2004 && value.as_str().is_some_and(|s| s.starts_with('#')),
        (_, "lineweight" | "insunits") => before_2000(version),
        ("MTEXT", f) if f.starts_with("background_") => before_2004,
        ("INSERT", "attributes.0.tag" | "attributes.0.mtext.text") => version != "R2018",
        ("VIEWPORT", "status" | "id" | "clip_boundary") => before_2000(version),
        ("dictionaries", "cloning") => before_2000(version),
        // A DWG gives a SHAPE's number in its shape file; the name is the
        // file's (spec 20.4.37).
        ("SHAPE", "name") => true,
        _ => false,
    }
}

/// What the converter writes differently in every version: a closed
/// periodic SPLINE is closed in its DWG (DXF 70 bit 1; its DXF of that DWG
/// sets periodic again, experiments/spline-flags), so of the flags the
/// closed and rational bits are compared.
fn same_as_written(ty: &str, field: &str, got: &Value, want: &Value) -> bool {
    match (ty, field) {
        ("SPLINE", "flags") => {
            let bits = |v: &Value| v.as_i64().unwrap_or(-1) & 5;
            bits(got) == bits(want)
        }
        _ => same(got, want),
    }
}

/// Check one file against what its source was given; return what was
/// checked and what failed.
fn check(file: &str, version: &str, source: &str, d: &Value) -> (usize, Vec<String>) {
    let mut checked = 0;
    let mut failed = Vec::new();
    for x in expected().iter().filter(|x| x["source"] == source) {
        let fields = x["fields"].as_object().expect("fields");
        let (what, target, ty) = if x.get("header").is_some() {
            ("header".to_string(), Some(&d["header"]), "")
        } else if let Some(table) = x["table"].as_str() {
            let name = x["name"].as_str().unwrap_or("");
            let key = x["key"].as_str().unwrap_or("name");
            let entry = d[table].as_array().and_then(|l| {
                l.iter()
                    .find(|e| e[key].as_str().is_some_and(|n| same_name(n, name)))
            });
            (format!("{table} {name}"), entry, table)
        } else {
            let handle = x["handle"].as_str().unwrap_or("");
            let ty = x["type"].as_str().unwrap_or("");
            let e = entity_by_handle(d, handle);
            // The model's dimension of every kind is a DIMENSION.
            let model_type = match ty {
                "ARC_DIMENSION" | "LARGE_RADIAL_DIMENSION" => "DIMENSION",
                t => t,
            };
            match e {
                Some(e) if e["type"] == model_type => {}
                _ if version == "R13" && NOT_IN_R13.contains(&ty) => continue,
                Some(e) => {
                    failed.push(format!("{file}: {ty} {handle} read as {}", e["type"]));
                    continue;
                }
                None => {
                    failed.push(format!("{file}: {ty} {handle} missing"));
                    continue;
                }
            }
            (format!("{ty} {handle}"), e, ty)
        };
        let Some(target) = target else {
            failed.push(format!("{file}: {what} missing"));
            continue;
        };
        for (path, want) in fields {
            if version_drops(version, ty, path, want) {
                continue;
            }
            checked += 1;
            match resolve(target, path) {
                Ok(got) if same_as_written(ty, path, &got, want) => {}
                // R13 and R14 symbol names are upper case.
                Ok(Value::String(got))
                    if before_2000(version)
                        && want.as_str().is_some_and(|w| same_name(w, &got)) => {}
                Ok(got) => failed.push(format!("{file}: {what} {path}: {got} != {want}")),
                Err(e) => failed.push(format!("{file}: {what} {path}: {e}")),
            }
        }
    }
    (checked, failed)
}

#[test]
fn every_conversion_reads_as_written() {
    let mut failed = Vec::new();
    for version in VERSIONS {
        for source in SOURCES {
            let file = format!("dwg/{version}/{source}.dwg");
            let d = dump(&dwg(version, source));
            let (checked, f) = check(&file, version, source, &d);
            assert!(checked > 0, "{file}: nothing checked");
            failed.extend(f);
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

/// The style a shape file is loaded through has DXF's flag 1, which the
/// specification's names for the STYLE bits would put at 4.
#[test]
fn a_shape_file_style_has_flag_1() {
    for version in VERSIONS {
        let d = dump(&dwg(version, "all"));
        let styles = d["text_styles"].as_array().expect("styles");
        let shx = styles
            .iter()
            .find(|s| s["font_file"] == "ltypeshp.shx")
            .expect("the shape file's style");
        assert_eq!(shx["flags"], 1, "{version}");
        assert!(
            styles
                .iter()
                .filter(|s| s["font_file"] != "ltypeshp.shx")
                .all(|s| s["flags"] == 0),
            "{version}"
        );
    }
}

/// A linetype dash without a shape or text: the converter writes no scale
/// (group 46) for it in DXF, so the DXF reader gives 1; the DWG stores 0.
fn clear_plain_dash_scales(d: &mut Value) {
    for lt in d["linetypes"].as_array_mut().into_iter().flatten() {
        for e in lt["elements"].as_array_mut().into_iter().flatten() {
            if e["flags"].as_i64().is_some_and(|f| f & 6 == 0) {
                e["scale"] = Value::Null;
            }
        }
    }
}

fn by<'a>(v: &'a Value, key: &str) -> Vec<(String, &'a Value)> {
    let mut out: Vec<_> = v
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| (e[key].as_str().unwrap_or("").to_string(), e))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// What the converter's DXF writes otherwise than its DWG holds, each
/// checked by the note `entity_diffs` gives (evidence in
/// tests/cad_dwg_oracle.rs): the `Standard` style left out, the knots and
/// control points of a fit-point spline and its computed flag bits, a clip
/// polygon's closing vertex, a LEADER's hookline direction without
/// annotation. A SHAPE's name is the shape file's, the DWG has its number.
const CONVERTER: [&str; 5] = [
    " (case)",
    " (fit points)",
    " (computed bits)",
    " (closed)",
    " (no annotation)",
];

/// The converter's DWG and DXF of one source and version keep the source's
/// handles: the two readings agree on everything the DWG reader reads.
#[test]
fn tables_and_blocks_equal_the_dxf_conversions() {
    let mut differ = Vec::new();
    for (version, source) in WITH_DXF
        .iter()
        .flat_map(|v| DXF_SOURCES.iter().map(move |s| (*v, *s)))
    {
        let mut a = dump(&dwg(version, source));
        let dxf = common::fixture(&format!("ascii/{version}/{source}.dxf")).expect("DXF");
        let source = format!("{version}/{source}");
        let dxf = exav_render::cad::read_dxf(&dxf).expect("DXF reads");
        let mut b: Value = serde_json::from_str(&exav_render::cad::to_json(&dxf)).expect("JSON");
        clear_plain_dash_scales(&mut a);
        clear_plain_dash_scales(&mut b);
        // The converter's DXF has objects of its own past the DWG's.
        a["header"]["handle_seed"] = Value::Null;
        b["header"]["handle_seed"] = Value::Null;
        let check = |x: &Value, y: &Value, what: String| {
            assert!(same(x, y), "{source} {what}:\n{x}\n{y}");
        };
        check(&a["header"], &b["header"], "header".into());
        for table in ["layers", "linetypes", "text_styles", "dim_styles", "vports"] {
            let (ta, tb) = (by(&a[table], "handle"), by(&b[table], "handle"));
            let keys = |t: &[(String, &Value)]| t.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
            assert_eq!(keys(&ta), keys(&tb), "{source} {table}");
            for ((h, x), (_, y)) in ta.iter().zip(&tb) {
                check(x, y, format!("{table} {h}"));
            }
        }
        let (ba, bb) = (by(&a["blocks"], "record"), by(&b["blocks"], "record"));
        assert_eq!(
            ba.iter().map(|x| &x.0).collect::<Vec<_>>(),
            bb.iter().map(|x| &x.0).collect::<Vec<_>>(),
            "{source} block records"
        );
        for ((h, x), (_, y)) in ba.iter().zip(&bb) {
            for (k, v) in x.as_object().into_iter().flatten() {
                if k != "entities" {
                    check(v, &y[k], format!("block {h} {k}"));
                }
            }
            let (ex, ey) = (
                x["entities"].as_array().expect("entities"),
                y["entities"].as_array().expect("entities"),
            );
            let handles = |l: &[Value]| l.iter().map(|e| e["handle"].clone()).collect::<Vec<_>>();
            assert_eq!(handles(ex), handles(ey), "{source} block {h} entities");
            for (e, f) in ex.iter().zip(ey) {
                for (path, x) in entity_diffs(e, f, "entity", &[]) {
                    let shape = e["type"] == "SHAPE" && path == "entity.name";
                    if !shape && !CONVERTER.iter().any(|n| path.ends_with(n)) {
                        differ.push(format!(
                            "{source} {} {}: {path} {x}",
                            e["type"], e["handle"]
                        ));
                    }
                }
            }
        }
        // The converter adds objects of its own to each file past the
        // source's handle seed.
        let src = common::fixture(&format!(
            "src/{}.dxf",
            source.split('/').nth(1).unwrap_or("")
        ))
        .expect("source");
        let seed = exav_render::cad::read_dxf(&src)
            .expect("source reads")
            .header
            .handle_seed
            .0;
        for (kind, h, found) in object_differences(&a, &b, seed) {
            for (path, x) in found {
                if !CONVERTER_OBJECTS.iter().any(|n| path.ends_with(n)) {
                    differ.push(format!("{source} {kind} {h}: {path} {x}"));
                }
            }
        }
    }
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

/// What the converter's DXF has otherwise than its DWG among the objects,
/// each checked by the note `object_differences` gives (evidence in
/// tests/cad_dwg_oracle.rs): objects it makes again or adds under handles
/// past the DWG's seed when it reads it, its round-trip data, dictionary
/// entries sorted by name, the *Active VPORT as the model layout's last
/// viewport.
const CONVERTER_OBJECTS: [&str; 5] = [
    " (remade)",
    " (added)",
    " (roundtrip)",
    " (order)",
    " (model)",
];

#[test]
fn the_code_page_is_the_files() {
    // The converter writes the source's ANSI_1251 text as `\U+` escapes in
    // its ANSI_1252 DWG; read back, the names are the Cyrillic ones.
    for version in VERSIONS {
        let d = dump(&dwg(version, "cp1251"));
        assert!(
            d["layers"]
                .as_array()
                .expect("layers")
                .iter()
                .any(|l| l["name"].as_str().is_some_and(|n| same_name(n, "Стены"))),
            "{version}"
        );
    }
}

fn quick<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{what} took {:?}",
        start.elapsed()
    );
    out
}

/// Cut short anywhere and with bits flipped anywhere, every fixture reads
/// or fails quickly, without a panic.
#[test]
fn damaged_files_return_quickly() {
    for version in VERSIONS {
        for source in SOURCES {
            let bytes = dwg(version, source);
            let step = (bytes.len() / 300).max(1);
            for cut in (0..bytes.len()).step_by(step) {
                let _ = quick(&format!("{version} {source} cut at {cut}"), || {
                    read_dwg(&bytes[..cut])
                });
            }
            let mut seed = 0x9E37_79B9_7F4A_7C15u64;
            for _ in 0..300 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let mut b = bytes.clone();
                let at = (seed as usize) % b.len();
                b[at] ^= 1 << (seed >> 61);
                let r = quick(&format!("{version} {source} flip at {at}"), || read_dwg(&b));
                if let Ok(d) = r {
                    assert!(d.warnings.len() <= Limits::default().max_warnings);
                }
            }
        }
    }
}

#[test]
fn what_is_not_a_dwg_this_reads_is_an_error() {
    assert_eq!(read_dwg(b"").err(), Some(Error::NotDwg));
    assert_eq!(read_dwg(b"%PDF-1.7").err(), Some(Error::NotDwg));
    assert_eq!(read_dwg(b"AC1015\0\0\0").err(), Some(Error::NotDwg));
    // A version ID without the encrypted (R2004) or coded (R2007) file
    // header after it.
    assert_eq!(read_dwg(b"AC1018\0\0\0\0\0\0").err(), Some(Error::NotDwg));
    assert_eq!(read_dwg(b"AC1021\0\0\0\0\0\0").err(), Some(Error::NotDwg));
    // An R2007 file whose header's codewords are all zeros.
    let mut zeros = dwg("R2007", "all");
    zeros[0x80..0x480].fill(0);
    let len = zeros.len();
    zeros[len - 0x400..].fill(0);
    assert_eq!(read_dwg(&zeros).err(), Some(Error::NotDwg));
}

/// A DWG of R12 or older is refused by its version, not as "not a DWG": the
/// viewer can then say why it is not shown. R12 is the ODA File Converter's
/// DWG of an ezdxf drawing (`exav-unpack/tests/fixtures/dwg/pre-r13`); an
/// R2.10 file's version ID does not start `AC10`, and its header is built
/// here as such files lay it out.
#[test]
fn a_drawing_older_than_r13_is_refused_by_its_version() {
    use exav_render::dwg::Document;
    let gz = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../exav-unpack/tests/fixtures/dwg/pre-r13/R12.dwg.gz"),
    )
    .expect("fixture");
    let r12 = common::gunzip(&gz);
    assert_eq!(
        read_dwg(&r12).err(),
        Some(Error::Unsupported("AC1009".to_string()))
    );
    let mut r2 = b"AC2.10\0\0\0\0\0\0\0\x03\0\x05\0\x53\0\0".to_vec();
    r2.extend_from_slice(&741u32.to_le_bytes());
    r2.extend_from_slice(&935u32.to_le_bytes());
    r2.resize(935, 0);
    for (bytes, id) in [(r12, "AC1009"), (r2, "AC2.10")] {
        let e = Document::parse(&bytes).err().expect("refused").0;
        assert!(e.contains(id) && e.contains("not supported"), "{id}: {e}");
    }
}

/// What the compressed sections of an R2004 to R2018 file expand to is
/// bounded: past the limit the file is refused, not read in part.
#[test]
fn the_decompression_limit_holds() {
    for version in ["R2004", "R2007", "R2010", "R2013", "R2018"] {
        let bytes = dwg(version, "all");
        let limits = Limits {
            max_decompressed_bytes: 50_000,
            ..Limits::default()
        };
        assert!(
            matches!(read_dwg_with(&bytes, &limits), Err(Error::LimitExceeded(_))),
            "{version}"
        );
        // Every section of the fixture fits in a few hundred kilobytes.
        let limits = Limits {
            max_decompressed_bytes: 1 << 20,
            ..Limits::default()
        };
        assert!(read_dwg_with(&bytes, &limits).is_ok(), "{version}");
    }
}

#[test]
fn the_entity_limit_holds() {
    let limits = Limits {
        max_entities: 3,
        ..Limits::default()
    };
    let d = read_dwg_with(&dwg("R2000", "all"), &limits).expect("reads");
    let n: usize = d.blocks.iter().map(|b| b.entities.len()).sum();
    assert_eq!(n, 3);
    assert!(d
        .warnings
        .iter()
        .any(|w| w.kind == WarningKind::LimitReached));
}

/// exav-unpack's preview fixtures: the converter made the bitmap its
/// make.py wrote (DIB.hex) each version's preview. The model carries it as a
/// BMP file, and `cad::preview` finds it without reading the drawing.
#[test]
fn the_preview_is_the_bitmap_the_drawing_was_given() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../exav-unpack/tests/fixtures/dwg/preview");
    let hex = std::fs::read_to_string(dir.join("DIB.hex")).expect("DIB.hex");
    let hex = hex.trim();
    let dib: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    for v in [
        "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
    ] {
        let gz = std::fs::read(dir.join(format!("{v}.dwg.gz"))).expect("fixture");
        let bytes = common::gunzip(&gz);
        let d = read_dwg(&bytes).unwrap_or_else(|e| panic!("{v}: {e}"));
        let p = d
            .preview
            .clone()
            .unwrap_or_else(|| panic!("{v}: no preview"));
        assert_eq!(p.format, exav_render::cad::PreviewFormat::Bmp, "{v}");
        assert_eq!(&p.data[..2], b"BM", "{v}");
        assert_eq!(&p.data[14..], &dib[..], "{v}");
        assert_eq!(exav_render::cad::preview(&bytes), Some(p), "{v}");
    }
    // A drawing saved without one has none.
    let plain = common::fixture("dwg/R2018/all.dwg").expect("fixture");
    assert_eq!(read_dwg(&plain).expect("read").preview, None);
    assert_eq!(exav_render::cad::preview(&plain), None);
}
