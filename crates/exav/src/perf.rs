//! `--profile` CSV output: turn a per-file [`exav_core::profile::Profile`] into a
//! row of a performance matrix (one column group per matcher). Kept out of
//! `main.rs` so the CLI entry point stays orchestration-only.

use exav_core::profile::Profile;
use std::borrow::Cow;
use std::fmt::Write;
use std::path::Path;
use std::time::Duration;

/// Matchers profiled by `--profile`, in fixed column order so the header and
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
    "static",
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
        text(&path.display().to_string()),
        size,
        verdict,
        text(signature),
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

/// A text field: neutralised, then quoted.
///
/// The two text columns are the only ones exav does not produce itself. The
/// path came off the filesystem being scanned and the signature name out of a
/// database, so both can be chosen by whoever chose what exav scanned — and
/// this file exists to be opened in a spreadsheet, where a cell starting `=`,
/// `+`, `-` or `@` is a formula rather than a string. Excel and Sheets both
/// treat a leading apostrophe as "this is text", so one in front costs a
/// character of display and takes the whole class away.
fn text(s: &str) -> Cow<'_, str> {
    let neutral: Cow<'_, str> = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        Cow::Owned(format!("'{s}"))
    } else {
        Cow::Borrowed(s)
    };
    match quote(&neutral) {
        // `quote` borrowed its argument, so the field is `neutral` unchanged.
        Cow::Borrowed(_) => neutral,
        Cow::Owned(q) => Cow::Owned(q),
    }
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
