//! `--perf-csv` output: turn a per-file [`exav_core::profile::Profile`] into a
//! row of a performance matrix (one column group per matcher). Kept out of
//! `main.rs` so the CLI entry point stays orchestration-only.

use exav_core::profile::Profile;
use std::borrow::Cow;
use std::fmt::Write;
use std::path::Path;
use std::time::Duration;

/// Matchers profiled by `--perf-csv`, in fixed column order so the header and
/// every row line up. Must match the names passed to `profile::timed` in the
/// scan path.
const MATCHERS: &[&str] = &[
    "engine",
    "yara",
    "hashes",
    "sections",
    "cdb",
    "fuzzy",
    "bytecode",
    "ml",
    "normalize",
];

/// The header row: metadata columns + `<matcher>_us/_calls/_bytes` per matcher.
/// Printed once before any data rows.
pub fn header() -> String {
    let mut cols = vec![
        "file".to_string(),
        "bytes".to_string(),
        "verdict".to_string(),
        "signature".to_string(),
        "wall_us".to_string(),
    ];
    for m in MATCHERS {
        cols.push(format!("{m}_us"));
        cols.push(format!("{m}_calls"));
        cols.push(format!("{m}_bytes"));
    }
    cols.join(",")
}

/// One data row: file metadata then each matcher's micros/calls/bytes (0 when
/// the matcher didn't run for this file).
pub fn row(
    path: &Path,
    verdict: &str,
    signature: &str,
    prof: Option<&Profile>,
    wall: Duration,
    size: u64,
) -> String {
    let mut row = format!(
        "{},{},{},{},{}",
        quote(&path.display().to_string()),
        size,
        verdict,
        quote(signature),
        wall.as_micros(),
    );
    for m in MATCHERS {
        let s = prof
            .and_then(|p| p.iter().find(|(n, _)| n == m).map(|(_, s)| s))
            .unwrap_or_default();
        let _ = write!(row, ",{},{},{}", s.ns / 1000, s.calls, s.bytes);
    }
    row
}

/// RFC-4180 quote a field only if it contains a comma, quote, or newline. Used
/// just for `file` and `signature`; every other column is a fixed name or an
/// integer we produce, so it needs no escaping.
fn quote(s: &str) -> Cow<'_, str> {
    if s.contains([',', '"', '\n', '\r']) {
        Cow::Owned(format!("\"{}\"", s.replace('"', "\"\"")))
    } else {
        Cow::Borrowed(s)
    }
}
