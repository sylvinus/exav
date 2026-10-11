//! exav-render's reading of DXF files against ezdxf's, entity by entity.
//!
//! `EXAV_DEBUG_CAD_CORPUS=<dir>` names a directory of `.dxf` files (searched
//! one level down too); without it the test only says it skipped. For each
//! file, `tests/cad_oracle/ezdxf_dump.py` writes the same JSON schema as
//! `exav_render::cad::to_json` from ezdxf's parse, and the two are compared: the
//! header, tables and objects by name or handle, blocks by name, and each
//! block's entities in order, every field, floats within a relative 1e-9.
//!
//! Differences whose cause is known and lies with the oracle are listed in
//! [`EXPLAINED`] with the reason; they are counted but do not fail the test.
//! Any other difference fails it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Differences explained on the oracle's side: a pattern (as [`Diffs::push`]
/// gives it) that starts and ends so, and why.
const EXPLAINED: &[(&str, &str, &str)] = &[
    // What a pre-2000 file does not have, which each reader makes up.
    ("pre-2000 layers.handle", "", R12_HANDLES),
    ("pre-2000 linetypes.handle", "", R12_HANDLES),
    ("pre-2000 text_styles.handle", "", R12_HANDLES),
    ("pre-2000 dim_styles.handle", "", R12_HANDLES),
    ("pre-2000 vports.handle", "", R12_HANDLES),
    ("pre-2000 block.handle", "", R12_HANDLES),
    ("pre-2000 block.record", "", R12_HANDLES),
    ("pre-2000 block.end_handle", "", R12_HANDLES),
    ("pre-2000 entity:", ".owner", R12_HANDLES),
    ("pre-2000 layouts", "", NO_LAYOUTS),
    ("pre-2000 block.layout", "", NO_LAYOUTS),
    ("pre-2000 dictionaries", "", EZDXF_UPGRADE),
    ("pre-2000 mleader_styles (only ezdxf)", "", EZDXF_UPGRADE),
    ("pre-2000 mline_styles (only ezdxf)", "", EZDXF_UPGRADE),
    ("pre-2000 block (only ezdxf) _", "", EZDXF_UPGRADE),
    ("pre-2000 linetypes (only ezdxf) BYBLOCK", "", EZDXF_UPGRADE),
    ("pre-2000 linetypes (only ezdxf) BYLAYER", "", EZDXF_UPGRADE),
    ("pre-2000 layers.plot_style", "", EZDXF_UPGRADE),
    ("pre-2000 layers.material", "", EZDXF_MATERIAL),
    ("layers.material", "", EZDXF_MATERIAL),
    ("dictionaries (only ezdxf)", "", EZDXF_MATERIAL),
    ("dictionaries.entries (length)", "", EZDXF_MATERIAL),
    ("pre-2000 layers (only ezdxf) DEFPOINTS", "", DEFPOINTS),
    ("layers (only ezdxf) DEFPOINTS", "", DEFPOINTS),
    ("pre-2000 layers.plot", "", DEFPOINTS),
    ("pre-2000 entity:VIEWPORT.", "", MVIEW),
    // Groups a file leaves out, which the reference gives no default for.
    ("pre-2000 block.scalable", "", SCALABLE),
    ("block.scalable", "", SCALABLE),
    ("pre-2000 dictionaries.hard_owner", "", HARD_OWNER),
    ("dictionaries.hard_owner", "", HARD_OWNER),
    ("dim_styles.dim", "", DIMSTYLE_DEFAULTS),
    ("entity:LEADER.hook", "", LEADER_DEFAULTS),
    ("entity:LEADER.text_", "", LEADER_DEFAULTS),
    ("pre-2000 entity:LEADER.hook", "", LEADER_DEFAULTS),
    ("pre-2000 entity:LEADER.text_", "", LEADER_DEFAULTS),
    ("entity:", ".style (case)", STANDARD),
    ("pre-2000 entity:", ".style (case)", STANDARD),
    ("entity:MTEXT.x_direction (absent)", "", MTEXT_DIRECTION),
    // What ezdxf reads differently.
    ("text_styles (only exav-render) (unnamed)", "", SHAPE_FILES),
    (
        "pre-2000 text_styles (only exav-render) (unnamed)",
        "",
        SHAPE_FILES,
    ),
    ("entity:ACAD_TABLE.", "", TABLE),
    ("entity:VIEWPORT.frozen_layers", "", FROZEN_341),
    ("entity:", ".graphics (only exav-render)", PROXY_GRAPHICS),
    (
        "pre-2000 entity:",
        ".graphics (only exav-render)",
        PROXY_GRAPHICS,
    ),
];

const PROXY_GRAPHICS: &str = "the dump of ezdxf's reading has no proxy graphics (the model \
    keeps them for the types it does not read); tests/cad_proxy.rs checks them against the \
    ODA converter's drawing of the same streams";

const FROZEN_341: &str = "a 2000 file lists a VIEWPORT's frozen layers in group 341 (every \
     handle names a LAYER); ezdxf reads only 331, the 2012 reference's code";

const R12_HANDLES: &str = "R12 table entries and blocks have no handle and R12 entities no \
     owner group: both readers number them, differently";
const NO_LAYOUTS: &str =
    "LAYOUT objects came with 2000: exav-render makes Model and Layout1 from the \
     header's limits and extents, ezdxf from its own template (an A3 page setup)";
const EZDXF_UPGRADE: &str =
    "ezdxf upgrades a pre-2000 drawing to its 2000 structure on load, adding \
     dictionaries, styles, plot styles, BYBLOCK/BYLAYER linetypes and arrow blocks";
const EZDXF_MATERIAL: &str = "ezdxf adds the MATERIAL objects (2007) a drawing lacks, with their \
     dictionary, and points layers without group 347 at them";
const DEFPOINTS: &str = "ezdxf adds the Defpoints layer when missing and forces it not to plot \
     (pre-2000 layers have no group 290)";
const MVIEW: &str = "before 2000 a VIEWPORT keeps its view in ACAD extended data after 1000 MVIEW \
     (the AcDbViewport class has only 10, 40, 41, 68, 69); ezdxf leaves its defaults";
const SCALABLE: &str =
    "group 281 of BLOCK_RECORD is absent before 2007; exav-render reads absent as \
     scalable, ezdxf as 0";
const HARD_OWNER: &str =
    "group 280 of DICTIONARY is absent; the reference gives no default, ezdxf \
     assumes 1 (its source says so: undocumented)";
const DIMSTYLE_DEFAULTS: &str = "the converter omits DIMSTYLE groups equal to AutoCAD's imperial \
     defaults (DIMASZ 0.18, DIMTXT 0.18, DIMEXO 0.0625, DIMEXE 0.18, DIMGAP 0.09): the header's \
     values for the current style agree in 696 of 702 corpus records; ezdxf fills metric defaults";
const LEADER_DEFAULTS: &str = "LEADER groups 74, 75, 40 and 41 are absent; the reference gives no \
     default, ezdxf assumes 1";
const STANDARD: &str = "group 7 absent: the reference's default is STANDARD, ezdxf's is Standard \
     (symbol table names are case-insensitive)";
const MTEXT_DIRECTION: &str = "group 11 absent from the MTEXT (rotation 0); ezdxf takes the \
     direction (1, 0, 0) from the 2018 embedded column data after group 101";
const SHAPE_FILES: &str = "a STYLE entry recording a shape file load has no name (reference, \
     STYLE: only group 3 is meaningful); ezdxf drops it, exav-render keeps it for SHAPE entities";
const TABLE: &str = "ACAD_TABLE repeats 90, 91, 92 in its cell data: the table's rows and \
     columns are the first (reference, ACAD_TABLE); ezdxf keeps the last, and does not read the \
     row heights (141) and column widths (142)";

#[derive(Default)]
struct Diffs {
    /// Pattern (paths without indices) to count and a few examples.
    by_pattern: BTreeMap<String, (usize, Vec<String>)>,
    /// The file being compared is older than 2000, whose files have no
    /// handles for table entries (R12), no LAYOUT objects and no OBJECTS
    /// section (R12): patterns are prefixed "pre-2000 ".
    r12: bool,
}

impl Diffs {
    fn push(&mut self, pattern: String, example: String) {
        let pattern = prefixed(self.r12, &pattern);
        let e = self.by_pattern.entry(pattern).or_default();
        e.0 += 1;
        if e.1.len() < 4 {
            e.1.push(example);
        }
    }
}

fn close(a: f64, b: f64) -> bool {
    a == b || (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1.0)
}

/// Compare two values; push one difference per differing leaf.
fn compare(a: &Value, b: &Value, path: &str, pattern: &str, found: &mut Vec<(String, String)>) {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (
                x.as_f64().unwrap_or(f64::NAN),
                y.as_f64().unwrap_or(f64::NAN),
            );
            if !close(x, y) {
                found.push((pattern.to_string(), format!("{path}: {x} vs {y}")));
            }
        }
        (Value::Object(x), Value::Object(y)) => {
            for (k, va) in x {
                let p = format!("{path}.{k}");
                let pat = format!("{pattern}.{k}");
                match y.get(k) {
                    Some(vb) => compare(va, vb, &p, &pat, found),
                    None => found.push((format!("{pat} (only exav-render)"), p)),
                }
            }
            for k in y.keys() {
                if !x.contains_key(k) {
                    found.push((format!("{pattern}.{k} (only ezdxf)"), format!("{path}.{k}")));
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                found.push((
                    format!("{pattern} (length)"),
                    format!("{path}: {} vs {}", x.len(), y.len()),
                ));
                return;
            }
            for (i, (va, vb)) in x.iter().zip(y).enumerate() {
                compare(
                    va,
                    vb,
                    &format!("{path}[{i}]"),
                    &format!("{pattern}[]"),
                    found,
                );
            }
        }
        _ if a == b => {}
        // Differences that are only ASCII case, or a null against the value
        // the model's absent default stands for, are told apart so that
        // they can be explained on their own.
        (Value::String(x), Value::String(y)) if x.eq_ignore_ascii_case(y) => {
            found.push((format!("{pattern} (case)"), format!("{path}: {a} vs {b}")));
        }
        (Value::Null, Value::Array(y)) if *y == [1.0, 0.0, 0.0] => {
            found.push((
                format!("{pattern} (absent)"),
                format!("{path}: null vs {b}"),
            ));
        }
        _ => {
            let show = |v: &Value| {
                let s = v.to_string();
                if s.len() > 80 {
                    format!(
                        "{}...",
                        &s[..s.char_indices().nth(77).map_or(s.len(), |(i, _)| i)]
                    )
                } else {
                    s
                }
            };
            found.push((
                pattern.to_string(),
                format!("{path}: {} vs {}", show(a), show(b)),
            ));
        }
    }
}

fn key_of(v: &Value, field: &str) -> String {
    v.get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_uppercase()
}

/// An unmatched entry's key in its pattern, when it is a name rather than a
/// handle: " DEFPOINTS", or " (unnamed)".
fn named(key: &str, field: &str) -> String {
    match key {
        _ if field == "handle" => String::new(),
        "" => " (unnamed)".to_string(),
        k => format!(" {k}"),
    }
}

/// Two lists matched by a key field; pairs compared, unmatched reported.
fn compare_keyed(what: &str, a: &Value, b: &Value, field: &str, file: &str, diffs: &mut Diffs) {
    let empty = Vec::new();
    let xs = a.as_array().unwrap_or(&empty);
    let ys = b.as_array().unwrap_or(&empty);
    let mut ys_by: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for y in ys {
        ys_by.entry(key_of(y, field)).or_default().push(y);
    }
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    for x in xs {
        let k = key_of(x, field);
        let n = used.entry(k.clone()).or_default();
        match ys_by.get(&k).and_then(|v| v.get(*n)) {
            Some(y) => {
                *n += 1;
                let mut found = Vec::new();
                compare(x, y, &format!("{what}[{k}]"), what, &mut found);
                for (p, e) in found {
                    diffs.push(p, format!("{file}: {e}"));
                }
            }
            None => diffs.push(
                format!("{what} (only exav-render){}", named(&k, field)),
                format!("{file}: {k}"),
            ),
        }
    }
    for (k, v) in &ys_by {
        let n = used.get(k).copied().unwrap_or(0);
        for _ in n..v.len() {
            diffs.push(
                format!("{what} (only ezdxf){}", named(k, field)),
                format!("{file}: {k}"),
            );
        }
    }
}

#[derive(Default)]
struct Totals {
    files: usize,
    both_read: usize,
    ours_failed: Vec<String>,
    oracle_failed: Vec<String>,
    entities: usize,
    entities_equal: usize,
    /// Equal, or different only in explained ways.
    entities_agree: usize,
    /// The same counts for 2000 and later files.
    entities_2000: usize,
    entities_2000_equal: usize,
}

fn prefixed(pre2000: bool, pattern: &str) -> String {
    if pre2000 {
        format!("pre-2000 {pattern}")
    } else {
        pattern.to_string()
    }
}

fn explained(pattern: &str) -> Option<&'static str> {
    EXPLAINED
        .iter()
        .find(|(start, end, _)| pattern.starts_with(start) && pattern.ends_with(end))
        .map(|(_, _, w)| *w)
}

fn compare_files(ours: &Value, theirs: &Value, file: &str, diffs: &mut Diffs, t: &mut Totals) {
    diffs.r12 = matches!(
        ours["header"]["version"].as_str(),
        Some("R12" | "R13" | "R14")
    );
    let mut found = Vec::new();
    compare(
        &ours["header"],
        &theirs["header"],
        "header",
        "header",
        &mut found,
    );
    for (p, e) in found {
        diffs.push(p, format!("{file}: {e}"));
    }
    for (table, field) in [
        ("layers", "name"),
        ("linetypes", "name"),
        ("text_styles", "name"),
        ("dim_styles", "name"),
        ("vports", "name"),
        ("layouts", "name"),
        ("dictionaries", "handle"),
        ("sort_tables", "handle"),
        ("image_defs", "handle"),
        ("underlay_defs", "handle"),
        ("mline_styles", "handle"),
        ("mleader_styles", "handle"),
    ] {
        compare_keyed(table, &ours[table], &theirs[table], field, file, diffs);
    }

    // Blocks by name, then their entities in order.
    let empty = Vec::new();
    let theirs_blocks = theirs["blocks"].as_array().unwrap_or(&empty);
    for b in ours["blocks"].as_array().unwrap_or(&empty) {
        let name = key_of(b, "name");
        let Some(tb) = theirs_blocks.iter().find(|x| key_of(x, "name") == name) else {
            diffs.push(format!("block (only exav-render) {name}"), file.to_string());
            continue;
        };
        let mut found = Vec::new();
        for (k, v) in b.as_object().into_iter().flatten() {
            if k != "entities" {
                compare(
                    v,
                    &tb[k],
                    &format!("block[{name}].{k}"),
                    &format!("block.{k}"),
                    &mut found,
                );
            }
        }
        for (p, e) in found {
            diffs.push(p, format!("{file}: {e}"));
        }
        let es = b["entities"].as_array().unwrap_or(&empty);
        let ts = tb["entities"].as_array().unwrap_or(&empty);
        if es.len() != ts.len() {
            diffs.push(
                "block.entities (count)".into(),
                format!("{file}: {name}: {} vs {}", es.len(), ts.len()),
            );
        }
        for (i, (e, te)) in es.iter().zip(ts).enumerate() {
            t.entities += 1;
            if !diffs.r12 {
                t.entities_2000 += 1;
            }
            let ty = e["type"].as_str().unwrap_or("?").to_string();
            let mut found = Vec::new();
            if e["type"] != te["type"] {
                found.push(("entity.type".to_string(), format!("{ty} vs {}", te["type"])));
            } else {
                compare(
                    e,
                    te,
                    &format!("{name}[{i}]"),
                    &format!("entity:{ty}"),
                    &mut found,
                );
            }
            if found.is_empty() {
                t.entities_equal += 1;
                if !diffs.r12 {
                    t.entities_2000_equal += 1;
                }
            }
            if found
                .iter()
                .all(|(p, _)| explained(&prefixed(diffs.r12, p)).is_some())
            {
                t.entities_agree += 1;
            }
            for (p, ex) in found {
                diffs.push(p, format!("{file}: {ex}"));
            }
        }
    }
    for tb in theirs_blocks {
        let name = key_of(tb, "name");
        let ours_has = ours["blocks"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .any(|x| key_of(x, "name") == name);
        if !ours_has {
            diffs.push(format!("block (only ezdxf) {name}"), file.to_string());
        }
    }
}

fn dxf_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(dxf_files(&p));
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("dxf")) {
            out.push(p);
        }
    }
    out.sort();
    out
}

#[test]
fn agrees_with_ezdxf_on_a_corpus() {
    let Some(dir) = std::env::var_os("EXAV_DEBUG_CAD_CORPUS") else {
        eprintln!("EXAV_DEBUG_CAD_CORPUS not set; skipping the ezdxf differential test");
        return;
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cad_oracle/ezdxf_dump.py");
    let files = dxf_files(Path::new(&dir));
    assert!(
        !files.is_empty(),
        "no .dxf file under {}",
        dir.to_string_lossy()
    );

    let mut diffs = Diffs::default();
    let mut t = Totals::default();
    let root = Path::new(&dir);
    for path in &files {
        t.files += 1;
        let name = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let bytes = std::fs::read(path).expect("read");
        let ours = exav_render::cad::read_dxf(&bytes);
        let out = Command::new("python3")
            .arg(&script)
            .arg(path)
            .output()
            .expect("python3");
        let theirs: Option<Value> = out
            .status
            .success()
            .then(|| serde_json::from_slice(&out.stdout).ok())
            .flatten();
        match (ours, theirs) {
            (Ok(d), Some(theirs)) => {
                t.both_read += 1;
                let ours: Value =
                    serde_json::from_str(&exav_render::cad::to_json(&d)).expect("our JSON");
                compare_files(&ours, &theirs, &name, &mut diffs, &mut t);
            }
            (Err(e), Some(_)) => t.ours_failed.push(format!("{name}: {e}")),
            (Ok(_), None) => t.oracle_failed.push(format!(
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .last()
                    .unwrap_or("")
            )),
            (Err(e), None) => t.oracle_failed.push(format!("{name}: both failed ({e})")),
        }
    }

    eprintln!(
        "\n{} files, {} read by both; exav-render failed on {}, ezdxf on {}",
        t.files,
        t.both_read,
        t.ours_failed.len(),
        t.oracle_failed.len()
    );
    for f in t.ours_failed.iter().chain(&t.oracle_failed) {
        eprintln!("  {f}");
    }
    let pct = |a: usize, b: usize| {
        if b > 0 {
            100.0 * a as f64 / b as f64
        } else {
            100.0
        }
    };
    eprintln!(
        "entities: {} compared, {} identical ({:.3}%), {} identical or explained ({:.3}%)",
        t.entities,
        t.entities_equal,
        pct(t.entities_equal, t.entities),
        t.entities_agree,
        pct(t.entities_agree, t.entities)
    );
    eprintln!(
        "  in 2000 and later files: {} compared, {} identical ({:.3}%)",
        t.entities_2000,
        t.entities_2000_equal,
        pct(t.entities_2000_equal, t.entities_2000)
    );
    let mut unexplained = 0;
    for (pattern, (count, examples)) in &diffs.by_pattern {
        match explained(pattern) {
            Some(w) => eprintln!("\n[explained] {pattern}: {count} ({w})"),
            None => {
                unexplained += count;
                eprintln!("\n{pattern}: {count}");
            }
        }
        for e in examples {
            eprintln!("    {e}");
        }
    }
    assert!(
        t.ours_failed.is_empty(),
        "exav-render failed on files ezdxf read"
    );
    assert_eq!(unexplained, 0, "unexplained differences with ezdxf");
}
