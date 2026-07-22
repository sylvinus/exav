#![no_main]
//! Single comprehensive fuzz target that populates every Scanner subsystem
//! from fuzz-generated text and exercises all major entry points:
//! `analyze()`, `analyze_all()`, `scan_seekable()`, and `scan_path()`.
//!
//! This replaces the need for separate per-subsystem targets. The input is
//! length-prefixed sections:
//!
//! ```text
//! [n_sections:1] [sec0_len:2BE] [sec0..] [sec1_len:2BE] [sec1..] ...
//! ```
//!
//! Sections:
//!  0 — NDB/LDB text (engine signatures)
//!  1 — HDB text    (whole-file hash sigs)
//!  2 — FDB text    (fuzzy TLSH/imphash sigs)
//!  3 — CDB text    (container metadata sigs)
//!  4 — IDB text    (PE icon hash sigs)
//!  5 — FP/IGN text (allowlist + ignore names)
//!  6 — scan data   (the bytes to scan)
//!
//! Every section is optional (zero-length = empty DB for that subsystem).

use std::io::Cursor;
use libfuzzer_sys::fuzz_target;
use exav_core::{
    analyze, analyze_all, database, scan_seekable, Scanner, ScanOptions,
};
use exav_core::engine::EngineBuilder;
use exav_core::hashes::HashDb;
use exav_core::fuzzy::FuzzyDb;
use exav_core::container::CdbDb;
use exav_core::icon::IconDb;

const NUM_SECTIONS: usize = 7;

fn read_u16_be(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(off)?, *buf.get(off + 1)?]))
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let n_sections = data[0] as usize;
    if n_sections > NUM_SECTIONS {
        return;
    }
    let mut pos = 1;
    let mut sections: Vec<&[u8]> = Vec::with_capacity(n_sections);
    for _ in 0..n_sections {
        let len = match read_u16_be(data, pos) {
            Some(l) => l as usize,
            None => return,
        };
        pos += 2;
        if pos + len > data.len() {
            return;
        }
        sections.push(&data[pos..pos + len]);
        pos += len;
    }
    let scan_data = data.get(pos..).unwrap_or(&[]);

    // Section 0: engine signatures (NDB + LDB)
    let engine_text = str_from(sections.get(0).copied().unwrap_or(&[]));
    let mut eb = EngineBuilder::new();
    if let Some(t) = engine_text {
        eb.add_ndb(t, false);
        eb.add_ldb(t, false);
    }
    let engine = eb.build();

    // Section 1: whole-file hash sigs (HDB/HSB)
    let mut hashes = HashDb::new();
    if let Some(t) = str_from(sections.get(1).copied().unwrap_or(&[])) {
        hashes.extend_from_text(t);
    }

    // Section 2: fuzzy sigs (FDB/IMP)
    let mut fuzzy = FuzzyDb::new();
    if let Some(t) = str_from(sections.get(2).copied().unwrap_or(&[])) {
        fuzzy.extend_from_text(t);
    }

    // Section 3: container metadata sigs (CDB)
    let mut cdb = CdbDb::new();
    if let Some(t) = str_from(sections.get(3).copied().unwrap_or(&[])) {
        cdb.extend_from_text(t);
    }

    // Section 4: icon hash sigs (IDB)
    let mut icons = IconDb::new();
    if let Some(t) = str_from(sections.get(4).copied().unwrap_or(&[])) {
        icons.extend_from_text(t);
    }

    // Section 5: allowlist + ignore (FP/IGN)
    let mut allow = HashDb::new();
    let mut ignored = std::collections::HashSet::new();
    if let Some(t) = str_from(sections.get(5).copied().unwrap_or(&[])) {
        allow.extend_from_text(t);
        // Also parse ignore-name lines (IGN2 format: just the name).
        for line in t.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                ignored.insert(line.to_string());
            }
        }
    }

    let db = Scanner::from_parts(engine, hashes, fuzzy, cdb, icons, allow, ignored);

    let opts = ScanOptions {
        heuristics: true,
        ..Default::default()
    };

    // --- Entry point 1: analyze (in-memory, primary path) ---
    let _ = analyze(&db, scan_data, &opts);

    // --- Entry point 2: analyze_all (all-match mode, no early termination) ---
    let _ = analyze_all(&db, scan_data, &opts);

    // --- Entry point 3: scan_seekable (Cursor = in-memory seekable reader) ---
    let cursor = Cursor::new(scan_data);
    let _ = scan_seekable(&db, cursor, scan_data.len() as u64, &opts);

    // --- Entry point 4: database round-trip (serialize → deserialize → scan) ---
    {
        let mut buf = Vec::with_capacity(4096);
        if database::write(&db, &mut buf).is_ok() {
            if let Ok(loaded) = database::read(buf.as_slice()) {
                let _ = analyze(&loaded, scan_data, &opts);
            }
        }
    }
});

fn str_from(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok()
}
