//! OneNote (`.one`) extraction tests against real malware samples.
//!
//! Fixtures are real-malware `.one` droppers, gitignored and kept locally in
//! password-protected ZIPs (`tests/fixtures/README.md`). The tests only carve
//! their embedded FileDataStoreObject payloads and assert the extractor is
//! panic-safe. See `tests/fixtures/onenote/README.md` for sha256 provenance.

use exav_unpack::{detect, extract, Budget, Format, Limits};

/// The `.one` samples present locally, as `(name, bytes)`, each kept in its
/// AES ZIP (`../README.md`).
fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = format!("{}/tests/fixtures/onenote", env!("CARGO_MANIFEST_DIR"));
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir}: {e}"))
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| Some(n.strip_suffix(".zip")?.to_string()))
        .filter(|n| n.ends_with(".one"))
        .collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|n| Some((n.clone(), super::real_sample(&format!("onenote/{n}"))?)))
        .collect()
}

#[test]
fn real_samples_detect_extract_and_never_panic() {
    let files = fixtures();
    if files.is_empty() {
        // Real-malware samples are gitignored; skip when they're absent
        // (fresh clone / CI). See tests/fixtures/onenote/README.md.
        eprintln!("skipping: no real-malware .one fixtures present locally");
        return;
    }
    let mut total_members = 0usize;
    for (name, data) in &files {
        // All samples are genuine OneNote sections → must be detected.
        assert_eq!(
            detect(data),
            Some(Format::OneNote),
            "not detected as OneNote: {name}"
        );
        // Extraction must complete without panicking on real (hostile) input.
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::OneNote, data, &mut budget)
            .unwrap_or_else(|e| panic!("extract {name}: {}", e.reason));
        total_members += entries.len();
    }
    // At least one real sample must yield an embedded member (these droppers
    // carry their payload as a FileDataStoreObject).
    assert!(
        total_members >= 1,
        "expected >=1 embedded member across the real samples, got {total_members}"
    );
}
