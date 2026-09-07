//! A nested detection must report WHERE it matched.
//!
//! This is not cosmetic. When a scan disagrees with another scanner, the first
//! question is whether exav matched wrongly or simply reached content the other
//! scanner never unpacked, and the match location is the answer. A hit inside
//! an extracted member that reports no location reads as a hit on the
//! container's own bytes, which is indistinguishable from a target-gating bug
//! (a PE-only signature appearing to fire on an RTF) until someone checks by
//! hand whether the signature's bytes are present in the container at all.
//!
//! Every site that returns a detection therefore has to record where it
//! matched. Recording is first-write-wins, so the assertion is that *some*
//! location is reported for a hit that is nested.

use exav_core::{scan_seekable_located, ScanOptions, Scanner, Verdict};
use std::io::Cursor;

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

fn eicar_db() -> Scanner {
    // The built-in baseline knows EICAR, which is all this test needs.
    Scanner::builtin()
}

/// Scan a buffer through the located entry point the daemon uses.
fn scan(db: &Scanner, blob: &[u8]) -> (exav_core::ScanReport, Option<String>) {
    scan_seekable_located(
        db,
        Cursor::new(blob.to_vec()),
        blob.len() as u64,
        &ScanOptions::default(),
    )
    .expect("scan")
}

/// A stored-only ZIP holding one member.
fn zip_with(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = {
        let mut c = !0u32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let cd = out.len() as u32;
    let mut c = Vec::new();
    c.extend_from_slice(b"PK\x01\x02");
    c.extend_from_slice(&20u16.to_le_bytes());
    c.extend_from_slice(&20u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&crc.to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(data.len() as u32).to_le_bytes());
    c.extend_from_slice(&(name.len() as u16).to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(name.as_bytes());
    let cl = c.len() as u32;
    out.extend_from_slice(&c);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cl.to_le_bytes());
    out.extend_from_slice(&cd.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn a_hit_inside_a_member_reports_its_location() {
    let db = eicar_db();
    let blob = zip_with("payload/evil.txt", eicar());
    let (report, location) = scan(&db, &blob);
    assert!(
        matches!(report.verdict, Verdict::Infected { .. }),
        "expected the nested EICAR to be detected"
    );
    let loc = location.expect(
        "a detection inside a ZIP member must report a location; \
         reporting none makes a nested hit look like a container-level match",
    );
    assert!(
        loc.contains("evil.txt"),
        "location should name the member that matched, got {loc:?}"
    );
}

#[test]
fn a_top_level_hit_reports_no_location() {
    // The converse: a hit on the scanned object itself has no member path, and
    // inventing one would be worse than omitting it.
    let db = eicar_db();
    let (report, location) = scan(&db, eicar());
    assert!(matches!(report.verdict, Verdict::Infected { .. }));
    assert!(
        location.is_none(),
        "a top-level detection must not claim a member location, got {location:?}"
    );
}
