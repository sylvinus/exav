//! The drawings `tests/fixtures/cad/make.py` writes with ezdxf, as the ODA
//! File Converter saved them in each version from R12 to 2018, ASCII and
//! binary, read back and checked against the values the script put in
//! (`tests/fixtures/cad/expected.json`): the script, not the reader, is the
//! oracle.

#[path = "cad_common/mod.rs"]
mod common;

use common::{entity_by_handle, expected, resolve, same, same_name};
use serde_json::Value;

const VERSIONS: [&str; 7] = ["R12", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018"];
const SOURCES: [&str; 3] = ["all", "gradient", "cp1251"];

/// Types R12 has no form of: the converter turns them into others (an
/// ELLIPSE or SPLINE into a POLYLINE, a HATCH or MTEXT into an anonymous
/// block, a RAY into a LINE) or leaves them out.
const NOT_IN_R12: [&str; 14] = [
    "ELLIPSE",
    "SPLINE",
    "LWPOLYLINE",
    "MTEXT",
    "LEADER",
    "MULTILEADER",
    "MLINE",
    "HATCH",
    "HELIX",
    "RAY",
    "XLINE",
    "WIPEOUT",
    "IMAGE",
    "PDFUNDERLAY",
];

/// Fields a version cannot hold, which the converter drops or approximates:
/// before 2004 true colours (group 420) and entity transparency (440); in
/// R12 also lineweights, layer transparency, entity linetype scales (48),
/// complex linetypes, `$INSUNITS` and `$MEASUREMENT`, and MINSERT grids,
/// which the converter writes as one INSERT.
fn version_drops(version: &str, field: &str, value: &Value) -> bool {
    let r12 = version == "R12";
    let before_2004 = r12 || version == "R2000";
    match field {
        "transparency" => before_2004,
        "color" => before_2004 && value.as_str().is_some_and(|s| s.starts_with('#')),
        "lineweight" | "alpha" | "linetype_scale" | "insunits" | "measurement" => r12,
        "rows" | "columns" | "row_spacing" | "column_spacing" => r12,
        f if f.starts_with("elements.1.") => r12,
        _ => false,
    }
}

fn dump(bytes: &[u8]) -> Value {
    let d = exav_render::cad::read_dxf(bytes).expect("a fixture reads");
    assert!(d.warnings.is_empty(), "{:?}", d.warnings);
    serde_json::from_str(&exav_render::cad::to_json(&d)).expect("JSON")
}

/// Check one file against what its source was given; return what was
/// checked and what failed.
fn check(file: &str, version: &str, source: &str, d: &Value) -> (usize, Vec<String>) {
    let r12 = version == "R12";
    let mut checked = 0;
    let mut failed = Vec::new();
    for x in expected().iter().filter(|x| x["source"] == source) {
        let fields = x["fields"].as_object().expect("fields");
        let (what, target) = if x.get("header").is_some() {
            ("header".to_string(), Some(&d["header"]))
        } else if let Some(table) = x["table"].as_str() {
            if r12 && table == "layouts" {
                // R12 has one paper space and no layout objects.
                continue;
            }
            let name = x["name"].as_str().unwrap_or("");
            let entry = d[table].as_array().and_then(|l| {
                l.iter()
                    .find(|e| e["name"].as_str().is_some_and(|n| same_name(n, name)))
            });
            (format!("{table} {name}"), entry)
        } else {
            let handle = x["handle"].as_str().unwrap_or("");
            let ty = x["type"].as_str().unwrap_or("");
            let e = entity_by_handle(d, handle);
            match e {
                Some(e) if e["type"] == ty => {}
                // Types R12 lacks, and paper space past the first layout.
                _ if r12
                    && (NOT_IN_R12.contains(&ty)
                        || ty == "VIEWPORT"
                        || fields.get("paper_space") == Some(&Value::Bool(true))) =>
                {
                    continue
                }
                Some(e) => {
                    failed.push(format!("{file}: {ty} {handle} read as {}", e["type"]));
                    continue;
                }
                None => {
                    failed.push(format!("{file}: {ty} {handle} missing"));
                    continue;
                }
            }
            (format!("{ty} {handle}"), e)
        };
        let Some(target) = target else {
            failed.push(format!("{file}: {what} missing"));
            continue;
        };
        for (path, want) in fields {
            if version_drops(version, path, want) {
                continue;
            }
            checked += 1;
            match resolve(target, path) {
                Ok(got) if same(&got, want) => {}
                // Symbol names are case-insensitive, and R12's are upper case.
                Ok(Value::String(got))
                    if r12 && want.as_str().is_some_and(|w| same_name(w, &got)) => {}
                Ok(got) => failed.push(format!("{file}: {what} {path}: {got} != {want}")),
                Err(e) => failed.push(format!("{file}: {what} {path}: {e}")),
            }
        }
    }
    (checked, failed)
}

/// Every DIMENSION names a block of the drawing that has its picture. (The
/// converter renumbers anonymous blocks, so the names the script saw do not
/// survive.)
fn dimension_blocks(file: &str, d: &Value) -> Vec<String> {
    let blocks = d["blocks"].as_array().cloned().unwrap_or_default();
    let mut failed = Vec::new();
    let dims = blocks
        .iter()
        .flat_map(|b| b["entities"].as_array().cloned().unwrap_or_default())
        .filter(|e| e["type"] == "DIMENSION");
    for e in dims {
        let name = e["block_name"].as_str().unwrap_or("");
        let found = blocks.iter().any(|b| {
            b["name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
                && b["entities"].as_array().is_some_and(|l| !l.is_empty())
        });
        if !found {
            failed.push(format!(
                "{file}: DIMENSION {} block {name:?} missing",
                e["handle"]
            ));
        }
    }
    failed
}

#[test]
fn every_conversion_reads_as_written() {
    let mut failed = Vec::new();
    for format in ["ascii", "binary"] {
        for version in VERSIONS {
            for source in SOURCES {
                let file = format!("{format}/{version}/{source}.dxf");
                let Some(bytes) = common::fixture(&file) else {
                    // The converter writes no gradient before 2004.
                    assert_eq!(source, "gradient", "{file} missing");
                    continue;
                };
                let d = dump(&bytes);
                let (checked, f) = check(&file, version, source, &d);
                assert!(checked > 0, "{file}: nothing checked");
                failed.extend(f);
                failed.extend(dimension_blocks(&file, &d));
            }
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

#[test]
fn ezdxf_sources_read_as_written() {
    let mut failed = Vec::new();
    for (file, source) in [
        ("src/all.dxf", "all"),
        ("src/all-binary.dxf", "all"),
        ("src/gradient.dxf", "gradient"),
        ("src/cp1251.dxf", "cp1251"),
    ] {
        let d = dump(&common::fixture(file).expect(file));
        failed.extend(check(file, "R2018", source, &d).1);
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

/// The binary form of each conversion reads as the same drawing as the
/// ASCII form.
#[test]
fn binary_and_ascii_read_alike() {
    for version in VERSIONS {
        for source in SOURCES {
            let ascii = common::fixture(&format!("ascii/{version}/{source}.dxf"));
            let binary = common::fixture(&format!("binary/{version}/{source}.dxf"));
            let (Some(a), Some(b)) = (ascii, binary) else {
                continue;
            };
            let (a, b) = (dump(&a), dump(&b));
            assert!(same(&a, &b), "{version} {source}: binary and ASCII differ");
        }
    }
    let a = dump(&common::fixture("src/all.dxf").expect("src"));
    let b = dump(&common::fixture("src/all-binary.dxf").expect("src"));
    assert!(same(&a, &b), "ezdxf's binary and ASCII differ");
}

#[test]
fn the_code_page_is_honoured_before_2007() {
    for version in ["R12", "R2000", "R2004"] {
        let d = dump(&common::fixture(&format!("ascii/{version}/cp1251.dxf")).expect("cp1251"));
        assert_eq!(
            d["header"]["code_page"]
                .as_str()
                .map(str::to_ascii_uppercase),
            Some("ANSI_1251".into()),
            "{version}"
        );
    }
    // The raw bytes really are Windows-1251, not UTF-8.
    let raw = common::fixture("src/cp1251.dxf").expect("cp1251");
    assert!(
        raw.windows(6).any(|w| w == b"\xcf\xf0\xe8\xe2\xe5\xf2"),
        "Привет in cp1251"
    );
}
