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

use exav_core::{ScanOptions, Scanner, Verdict, scan_seekable_located};
use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
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

/// What a location does to a member's name. A control character (C0, DEL,
/// C1), a bidirectional control (U+061C, U+200E, U+200F, U+202A to U+202E,
/// U+2066 to U+2069) and U+2028 / U+2029 become `_`, so a name cannot add a
/// line to what prints the location or make it read in another order, and a
/// name keeps its first 200 characters.
#[test]
fn a_location_replaces_control_and_bidirectional_characters() {
    let db = eicar_db();
    let written = format!(
        "a\nb\u{1b}c\u{85}d\u{7f}e\u{202e}f\u{2028}g\u{2029}h\u{2066}i\u{61c}j\u{200f}k{}",
        "z".repeat(300)
    );
    let shown_head = "a_b_c_d_e_f_g_h_i_j_k";
    let shown = format!(
        "{shown_head}{}",
        "z".repeat(200 - shown_head.chars().count())
    );
    let blob = zip_with(&written, eicar());
    let (report, location) = scan(&db, &blob);
    assert!(matches!(report.verdict, Verdict::Infected { .. }));
    assert_eq!(location.as_deref(), Some(shown.as_str()));
}

/// A ZIP of one deflated member, so that what it holds is in no byte of it.
fn zip_deflated(name: &str, data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = ZipWriter::new(Cursor::new(Vec::new()));
    z.start_file(name, FileOptions::default().method(Method::Deflated))
        .unwrap();
    z.write_all(data).unwrap();
    z.finish().unwrap().into_inner()
}

/// A script carrying a PE, with EICAR in it, as base64.
fn script_with_encoded_pe() -> Vec<u8> {
    use base64::Engine as _;
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
    pe[0x80..0x80 + eicar().len()].copy_from_slice(eicar());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
    format!(
        "# dropper\r\n$PEBytes = \"{b64}\"\r\nInvoke-ReflectivePEInjection -PEBytes $PEBytes\r\n"
    )
    .into_bytes()
}

/// A payload decoded out of a text has no name in its container: it is named
/// by its place among the payloads of the text, below the text's own path.
#[test]
fn a_payload_decoded_from_a_text_is_located_by_its_own_name_below_the_text() {
    let db = eicar_db();
    let script = script_with_encoded_pe();
    let (report, location) = scan(&db, &script);
    assert!(
        matches!(report.verdict, Verdict::Infected { .. }),
        "{report:?}"
    );
    assert_eq!(location.as_deref(), Some("base64-payload-1"));
    // Deflated, so the text is not in the bytes of the ZIP to be decoded from
    // there first.
    let (report, location) = scan(&db, &zip_deflated("scripts/drop.ps1", &script));
    assert!(
        matches!(report.verdict, Verdict::Infected { .. }),
        "{report:?}"
    );
    assert_eq!(
        location.as_deref(),
        Some("scripts/drop.ps1/base64-payload-1")
    );
}

/// An asset of a page is named for its place among the assets, below the page.
#[test]
fn an_asset_of_a_page_is_located_by_its_own_name_below_the_page() {
    use base64::Engine as _;
    // A run is an asset when it starts with an image's magic.
    let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
    image.extend(std::iter::repeat_n(b'.', 64));
    image.extend_from_slice(eicar());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&image);
    let page =
        format!("<html><body><img src=\"data:image/png;base64,{b64}\"></body></html>").into_bytes();
    let (report, location) = scan(&eicar_db(), &page);
    assert!(
        matches!(report.verdict, Verdict::Infected { .. }),
        "{report:?}"
    );
    assert_eq!(location.as_deref(), Some("embedded-asset-1"));
}

/// A rule on what a container says of a member (its name, size, place) is
/// matched before any of its bytes are, and a hit is located at the member.
#[test]
fn a_hit_on_what_a_container_says_of_a_member_is_located_at_the_member() {
    let mut l = exav_core::loader::Builder::new();
    l.add_named_bytes(
        "t.cdb",
        b"Test.Cdb.Name:CL_TYPE_ZIP:*:evil\\.txt:*:*:*:*:*:*\n",
        true,
    );
    let db = l.build().expect("build database");
    let inner = zip_with("dir/evil.txt", b"harmless words");
    let blob = zip_with("outer/in.zip", &inner);
    let (report, location) = scan(&db, &blob);
    match report.verdict {
        Verdict::Infected { ref signature, .. } => {
            assert!(signature.contains("Test.Cdb.Name"), "{signature}")
        }
        ref other => panic!("{other:?}"),
    }
    assert_eq!(location.as_deref(), Some("outer/in.zip/dir/evil.txt"));
}

/// What is carved out of an object, or read from it a second way, has no
/// segment of its own: a hit in a member of an archive appended to a file is
/// at the member's name, as if the archive were the file.
#[test]
fn an_archive_found_after_the_end_of_a_file_adds_no_segment_to_a_location() {
    let db = eicar_db();
    // A PDF with a ZIP appended: read as a PDF, and a second time as the ZIP.
    let mut blob =
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
            .to_vec();
    let mut payload = eicar().to_vec();
    payload.extend(std::iter::repeat_n(b'A', 2000));
    blob.extend(zip_deflated("inside/evil.txt", &payload));
    let (report, location) = scan(&db, &blob);
    assert!(
        matches!(report.verdict, Verdict::Infected { .. }),
        "{report:?}"
    );
    assert_eq!(location.as_deref(), Some("inside/evil.txt"));
}

/// An alert for a bound reached inside a container is located where the bound
/// was reached: the container whose members ran past it.
#[test]
fn an_alert_for_a_bound_is_located_at_the_container_that_reached_it() {
    let db = eicar_db();
    let big: Vec<u8> = (0..4000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let inner = zip_with("big.bin", &big);
    let middle = zip_with("in.zip", &inner);
    let outer = zip_with("dir/mid.zip", &middle);
    let mut opts = ScanOptions::default();
    opts.alert_exceeds_max = true;
    // Each member is read within the budget, and charged to it once its
    // container is done with it: the bytes of `big.bin` are charged by
    // `in.zip`'s walk, and those of `in.zip` by `dir/mid.zip`'s, which is
    // where the budget runs out.
    opts.limits.max_scanned_bytes = 6000;
    let (report, location) =
        scan_seekable_located(&db, Cursor::new(outer.clone()), outer.len() as u64, &opts)
            .expect("scan");
    match report.verdict {
        Verdict::Infected { ref signature, .. } => {
            assert!(
                signature.starts_with("Heuristics.Limits.Exceeded"),
                "{signature}"
            )
        }
        ref other => panic!("{other:?}"),
    }
    assert_eq!(location.as_deref(), Some("dir/mid.zip"));
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
