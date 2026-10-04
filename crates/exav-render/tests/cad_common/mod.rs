//! Shared by the integration tests: the committed fixtures, unzipped, and
//! what `tests/fixtures/cad/make.py` says it wrote into them.

#![allow(dead_code)]

use std::io::Read;
use std::path::Path;

use serde_json::Value;

pub mod compare;

/// A fixture by its path under `tests/fixtures/cad`, without `.gz`; `None` when
/// the file does not exist (a version the converter cannot write).
pub fn fixture(path: &str) -> Option<Vec<u8>> {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cad")
        .join(format!("{path}.gz"));
    let gz = std::fs::read(full).ok()?;
    Some(gunzip(&gz))
}

pub fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("a gzip fixture");
    out
}

/// A path into a dump: `a.0.b`, `a#` for a list's length, `a.*.b` for the
/// list of `b` over `a`.
pub fn resolve(v: &Value, path: &str) -> Result<Value, String> {
    let (head, rest) = match path.split_once('.') {
        Some((h, r)) => (h, Some(r)),
        None => (path, None),
    };
    if head == "*" {
        let items = v.as_array().ok_or(format!("{path}: not a list"))?;
        let rest = rest.ok_or("* at the end")?;
        return items
            .iter()
            .map(|i| resolve(i, rest))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    let (name, count) = match head.strip_suffix('#') {
        Some(n) => (n, true),
        None => (head, false),
    };
    let next = match name.parse::<usize>() {
        Ok(i) => v.get(i),
        Err(_) => v.get(name),
    }
    .ok_or(format!("no {name}"))?;
    if count {
        let n = next.as_array().ok_or(format!("{name}: not a list"))?.len();
        return Ok(Value::from(n));
    }
    match rest {
        Some(r) => resolve(next, r),
        None => Ok(next.clone()),
    }
}

/// Equal, numbers within 1e-6 relative: the converter writes 16 significant
/// digits, and the script's degrees go through two conversions.
pub fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (
                x.as_f64().unwrap_or(f64::NAN),
                y.as_f64().unwrap_or(f64::NAN),
            );
            (x - y).abs() <= 1e-6 * x.abs().max(y.abs()).max(1.0)
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// Symbol names compare without case, Unicode's: R12 names are upper case,
/// Cyrillic ones included.
pub fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

pub fn entity_by_handle<'a>(d: &'a Value, handle: &str) -> Option<&'a Value> {
    d["blocks"]
        .as_array()?
        .iter()
        .flat_map(|b| b["entities"].as_array().into_iter().flatten())
        .find(|e| e["handle"] == handle)
}

/// `tests/fixtures/cad/expected.json`: per entity handle or table entry
/// name, field paths and the values the script gave them.
pub fn expected() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/cad/expected.json"
    );
    let text = std::fs::read_to_string(path).expect("expected.json");
    serde_json::from_str::<Vec<Value>>(&text).expect("expected.json parses")
}
