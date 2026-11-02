//! The 3D and CAD readers on files nested as deep as the file is long.
//!
//! glTF is JSON, IFC nests parentheses and refers from instance to instance,
//! DXF refers from block to block. Each has a depth limit, and each is read here
//! on a 512 KB stack with nesting well past it: the reader may refuse, but it has
//! to end, in seconds, without a panic.

#![cfg(any(feature = "gltf", feature = "ifc", feature = "dwg"))]

use std::time::{Duration, Instant};

const STACK: usize = 512 * 1024;
const N: usize = 100_000;

fn on_small_stack(name: &str, f: impl FnOnce() + Send + 'static) -> Option<String> {
    let started = Instant::now();
    let r = std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(f)
        .unwrap()
        .join();
    match r {
        Err(_) => Some(format!("{name}: overflowed its stack or panicked")),
        Ok(()) if started.elapsed() > Duration::from_secs(20) => Some(format!(
            "{name}: took {:.1} s",
            started.elapsed().as_secs_f64()
        )),
        Ok(()) => None,
    }
}

fn assert_all(findings: Vec<Option<String>>) {
    let findings: Vec<String> = findings.into_iter().flatten().collect();
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}

#[cfg(feature = "gltf")]
#[test]
fn gltf_json() {
    let head = "{\"asset\":{\"version\":\"2.0\"},\"extras\":";
    let cases: Vec<(&str, String)> = vec![
        ("arrays", format!("{head}{}{}}}", "[".repeat(N), "]".repeat(N))),
        ("objects", format!("{head}{}1{}}}", "{\"a\":".repeat(N), "}".repeat(N))),
        ("mixed", format!("{head}{}1{}}}", "[{\"a\":".repeat(N), "}]".repeat(N))),
        ("unclosed", format!("{head}{}", "[".repeat(N))),
        ("strings", format!("{head}\"{}\"}}", "\\u0041\\\"".repeat(N))),
        ("scenes", format!("{{\"asset\":{{\"version\":\"2.0\"}},\"nodes\":[{}],\"scenes\":[{{\"nodes\":[0]}}]}}", (0..N).map(|i| format!("{{\"children\":[{}]}}", i + 1)).collect::<Vec<_>>().join(","))),
        ("node cycle", "{\"asset\":{\"version\":\"2.0\"},\"nodes\":[{\"children\":[1]},{\"children\":[0]}],\"scenes\":[{\"nodes\":[0]}]}".to_string()),
    ];
    assert_all(
        cases
            .into_iter()
            .map(|(name, doc)| {
                on_small_stack(&format!("gltf {name}"), move || {
                    let _ = exav_render::gltf::read(doc.as_bytes(), 1 << 20);
                })
            })
            .collect(),
    );
}

#[cfg(feature = "ifc")]
#[test]
fn ifc_instances() {
    let step = |data: String| {
        format!(
            "ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4X3_ADD2'));\nENDSEC;\nDATA;\n{data}ENDSEC;\nEND-ISO-10303-21;\n"
        )
    };
    let chain = |f: &dyn Fn(usize) -> String| {
        (1..N)
            .map(|i| format!("#{i}={};\n", f(i)))
            .collect::<String>()
    };
    let cases: Vec<(&str, String)> = vec![
        ("aggregates", step(format!("#1=IFCWALL({}{});\n", "(".repeat(N), ")".repeat(N)))),
        ("lists", step(format!("#1=IFCWALL({}$;\n", "(".repeat(N)))),
        ("typed values", step(format!("#1=IFCWALL({}1.{});\n", "IFCLABEL(".repeat(N), ")".repeat(N)))),
        ("strings", step(format!("#1=IFCWALL('{}');\n", "''".repeat(N)))),
        ("placements", step(chain(&|i| format!("IFCLOCALPLACEMENT(#{},#{})", i + 1, i + 1)))),
        ("curves", step(chain(&|i| format!("IFCTRIMMEDCURVE(#{},(#{}),(#{}),.T.,.CARTESIAN.)", i + 1, i + 1, i + 1)))),
        ("profiles", step(chain(&|i| format!("IFCDERIVEDPROFILEDEF(.AREA.,$,#{},#{},$)", i + 1, i + 1)))),
        ("items", step(chain(&|i| format!("IFCMAPPEDITEM(#{},#{})", i + 1, i + 1)))),
        ("booleans", step(chain(&|i| format!("IFCBOOLEANRESULT(.DIFFERENCE.,#{},#{})", i + 1, i + 1)))),
        ("units", step(chain(&|i| format!("IFCCONVERSIONBASEDUNIT(#{},.LENGTHUNIT.,'x',#{})", i + 1, i + 1)))),
        ("styles", step(chain(&|i| format!("IFCSTYLEDITEM(#{},(#{}),$)", i + 1, i + 1)))),
        ("cycle", step("#1=IFCLOCALPLACEMENT(#2,#3);\n#2=IFCLOCALPLACEMENT(#1,#3);\n#3=IFCAXIS2PLACEMENT3D($,$,$);\n".to_string())),
    ];
    assert_all(
        cases
            .into_iter()
            .map(|(name, doc)| {
                on_small_stack(&format!("ifc {name}"), move || {
                    let _ = exav_render::ifc::read(
                        doc.as_bytes(),
                        &exav_render::ifc::Limits::default(),
                    );
                })
            })
            .collect(),
    );
}

#[cfg(feature = "dwg")]
#[test]
fn dxf_blocks() {
    let pair = |code: u32, v: &str| format!("{code}\n{v}\n");
    let sections = |blocks: String, entities: String| {
        format!(
            "{}{}{blocks}{}{}{}{entities}{}{}",
            pair(0, "SECTION"),
            pair(2, "BLOCKS"),
            pair(0, "ENDSEC"),
            pair(0, "SECTION"),
            pair(2, "ENTITIES"),
            pair(0, "ENDSEC"),
            pair(0, "EOF"),
        )
    };
    let block = |name: String, inner: String| {
        format!(
            "{}{}{}{inner}{}",
            pair(0, "BLOCK"),
            pair(2, &name),
            pair(8, "0"),
            pair(0, "ENDBLK")
        )
    };
    let insert = |name: String| {
        format!(
            "{}{}{}{}",
            pair(0, "INSERT"),
            pair(2, &name),
            pair(10, "0"),
            pair(20, "0")
        )
    };
    let chain: String = (0..N / 10)
        .map(|i| block(format!("B{i}"), insert(format!("B{}", i + 1))))
        .collect();
    let cycle = block("A".into(), insert("B".into())) + &block("B".into(), insert("A".into()));
    let cases: Vec<(&str, String)> = vec![
        ("an insert chain", sections(chain, insert("B0".into()))),
        ("an insert cycle", sections(cycle, insert("A".into()))),
        (
            "a self insert",
            sections(block("A".into(), insert("A".into())), insert("A".into())),
        ),
        (
            "many inserts",
            sections(
                block("A".into(), "".into()),
                insert("A".into()).repeat(N / 10),
            ),
        ),
        (
            "polylines",
            sections(
                String::new(),
                format!(
                    "{}{}",
                    pair(0, "POLYLINE"),
                    format!("{}{}", pair(0, "VERTEX"), pair(10, "1")).repeat(N)
                ),
            ),
        ),
        (
            "groups",
            format!("{}{}", pair(0, "SECTION"), "0\nSECTION\n".repeat(N)),
        ),
    ];
    assert_all(
        cases
            .into_iter()
            .map(|(name, doc)| {
                on_small_stack(&format!("dxf {name}"), move || {
                    let _ = exav_render::cad::read_dxf(doc.as_bytes());
                })
            })
            .collect(),
    );
}
