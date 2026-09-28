//! Size caps inside the scan must never pass as a complete scan.
//!
//! Each case here was a check that quietly ran on part of its input, or not at
//! all, while the file could still be reported `OK`: the DLP and phishing
//! heuristics above 16 MiB, the JavaScript normaliser's output cap, the UDF
//! tree of an ISO image, and the typing of a top-level input too large to
//! buffer.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};
use std::io::{Cursor, Read};
#[cfg(feature = "all-formats")]
use {exav_core::scan_seekable, std::io::Write};

/// Past the 16 MiB the DLP and phishing checks used to stop at.
const BIG: usize = 17 * 1024 * 1024;

fn filler_text(len: usize) -> Vec<u8> {
    let line = b"lorem ipsum dolor sit amet, consectetur adipiscing elit\n";
    line.iter().copied().cycle().take(len).collect()
}

fn expect_infected(v: Verdict, want: &str) {
    match v {
        Verdict::Infected { signature, .. } => assert_eq!(signature, want),
        other => panic!("expected {want}, got {other:?}"),
    }
}

fn expect_eicar(v: Verdict) {
    match v {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("the payload must be reached, got {other:?}"),
    }
}

#[test]
#[cfg(feature = "dlp")]
fn dlp_counts_past_16_mib() {
    let mut data = filler_text(BIG);
    data.extend_from_slice(b"card: 4111 1111 1111 1111\n");
    let mut opts = ScanOptions::default();
    opts.structured_cc_count = Some(1);
    expect_infected(
        analyze(&Scanner::builtin(), &data, &opts).verdict,
        "Heuristics.Structured.CreditCardNumber",
    );
}

const SPOOF: &[u8] = br#"<a href="http://evil.example/login">https://www.paypal.com/signin</a>"#;

#[test]
#[cfg(feature = "phishing")]
fn phishing_checks_past_16_mib() {
    let mut data = b"<html><body><p>".to_vec();
    data.extend_from_slice(&filler_text(BIG));
    data.extend_from_slice(SPOOF);
    data.extend_from_slice(b"</p></body></html>\n");
    let mut opts = ScanOptions::default();
    opts.alert_phishing = true;
    expect_infected(
        analyze(&Scanner::builtin(), &data, &opts).verdict,
        "Heuristics.Phishing.Email.SpoofedDomain",
    );
}

#[test]
#[cfg(feature = "phishing")]
fn phishing_checks_every_link() {
    // A newsletter or a mailbox easily carries thousands of links. The check
    // used to stop at the 4096th, so a spoofed one after them was never seen.
    let mut data = b"<html><body>\n".to_vec();
    for _ in 0..5000 {
        data.extend_from_slice(b"<a href=\"http://example.com/p\">example.com</a>\n");
    }
    data.extend_from_slice(SPOOF);
    data.extend_from_slice(b"\n</body></html>\n");
    let mut opts = ScanOptions::default();
    opts.alert_phishing = true;
    expect_infected(
        analyze(&Scanner::builtin(), &data, &opts).verdict,
        "Heuristics.Phishing.Email.SpoofedDomain",
    );
}

fn script_with_literal(len: usize) -> Vec<u8> {
    let mut data = b"eval(s);\nvar s=\"".to_vec();
    data.extend(std::iter::repeat_n(b'A', len));
    data.extend_from_slice(b"\";\n");
    data
}

#[test]
fn a_truncated_javascript_view_is_not_clean() {
    // The normalised script is cut at 32 MiB. The raw bytes are still scanned
    // in full, but a signature written against the normalised form cannot
    // match past the cut, so the scan is incomplete.
    let data = script_with_literal(33 * 1024 * 1024);
    match analyze(&Scanner::builtin(), &data, &ScanOptions::default()).verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
}

#[test]
fn a_whole_javascript_view_is_clean() {
    // Past the 8 MiB the view used to stop at.
    let data = script_with_literal(20 * 1024 * 1024);
    assert_eq!(
        analyze(&Scanner::builtin(), &data, &ScanOptions::default()).verdict,
        Verdict::Clean
    );
}

/// A UDF image from the exav-unpack fixtures, where the EICAR file sits
/// deflated inside `nested/deeper/payload.zip`, so no raw pass sees it.
/// `udf_only` is a `genisoimage -udf` image with its ISO 9660 descriptors
/// blanked; `bridge` carries both trees over the same extents; `metadata` is
/// UDF 2.50 with its tree in a metadata partition.
fn udf_fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/udf/{name}.iso.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let gz = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(Cursor::new(gz))
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("gunzip {p}: {e}"));
    let eicar = exav_core::unpack::eicar();
    assert!(
        !out.windows(eicar.len()).any(|w| w == eicar),
        "{name} must not expose the payload in its own bytes"
    );
    out
}

fn tiny_deep_analysis(max: u64) -> ScanOptions {
    let mut o = ScanOptions::default();
    o.deep_analysis_max = max;
    o
}

#[test]
#[cfg(feature = "all-formats")]
fn a_udf_only_image_is_walked() {
    // No ISO 9660 tree at all: the files are reachable through UDF only.
    let db = Scanner::builtin();
    for name in ["udf_only", "metadata"] {
        let blob = udf_fixture(name);
        expect_eicar(analyze(&db, &blob, &ScanOptions::default()).verdict);
        let size = blob.len() as u64;
        expect_eicar(
            scan_seekable(&db, Cursor::new(blob), size, &ScanOptions::default())
                .expect("scan")
                .verdict,
        );
    }
}

#[test]
#[cfg(feature = "all-formats")]
fn an_iso_too_large_to_buffer_is_walked() {
    // The volume descriptors sit at 32 KiB, past the 4 KiB a large input used
    // to be typed from, so the image was never recognised and only got the
    // literal pass.
    let db = Scanner::builtin();
    for name in ["bridge", "udf_only", "metadata"] {
        let blob = udf_fixture(name);
        let size = blob.len() as u64;
        let opts = tiny_deep_analysis(64 * 1024);
        assert!(size > opts.deep_analysis_max);
        expect_eicar(
            scan_seekable(&db, Cursor::new(blob), size, &opts)
                .expect("scan")
                .verdict,
        );
    }
}

#[test]
#[cfg(feature = "all-formats")]
fn walking_an_input_too_large_to_buffer_still_reports_the_limit() {
    // Its own bytes got the literal pass only, whatever the walk found in it.
    // The loader's baseline EICAR signature is ignored, so the payloads in the
    // fixtures do not count as a find.
    let mut l = exav_core::loader::Builder::new();
    l.add_named_bytes("t.ndb", b"Zzz.Never:0:*:deadbeefdeadbeefdead\n", true);
    l.add_named_bytes("t.ign2", b"Eicar-Test-Signature\n", true);
    let db = l.build().expect("build database");
    // A stub whose ZIP magic starts nothing: the walk fails on it.
    let mut false_sfx = b"MZ".to_vec();
    false_sfx.resize(64 * 1024, 0x90);
    false_sfx.extend_from_slice(b"PK\x03\x04 not an archive");
    for blob in [udf_fixture("bridge"), udf_fixture("udf_only"), false_sfx] {
        let size = blob.len() as u64;
        match scan_seekable(&db, Cursor::new(blob), size, &tiny_deep_analysis(16 * 1024))
            .expect("scan")
            .verdict
        {
            Verdict::LimitsExceeded { .. } => {}
            other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
        }
    }
}

#[test]
#[cfg(feature = "all-formats")]
fn an_sfx_too_large_to_buffer_is_walked() {
    // An executable stub with a ZIP appended past the first 64 KiB. The member
    // is padded so deflate codes it instead of storing EICAR as it is.
    let eicar = exav_core::unpack::eicar();
    let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("eicar.com", deflated).unwrap();
    z.write_all(eicar).unwrap();
    z.write_all(&[b'x'; 4096]).unwrap();
    let payload = z.finish().unwrap().into_inner();

    let mut blob = b"MZ".to_vec();
    blob.resize(64 * 1024, 0x90);
    blob.extend_from_slice(&payload);
    assert!(!blob.windows(eicar.len()).any(|w| w == eicar));
    let size = blob.len() as u64;
    let opts = tiny_deep_analysis(16 * 1024);
    assert!(payload.len() as u64 <= opts.deep_analysis_max);
    expect_eicar(
        scan_seekable(&Scanner::builtin(), Cursor::new(blob), size, &opts)
            .expect("scan")
            .verdict,
    );
}
