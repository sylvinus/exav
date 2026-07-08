//! OneNote (`.one`) extraction tests against real malware samples.
//!
//! Fixtures are real-malware `.one` droppers (defanged as inert data here — we
//! only carve their embedded FileDataStoreObject payloads and assert the
//! extractor is panic-safe). Living in `tests/fixtures/onenote/`; see that dir's
//! `README.md` for sha256 provenance.

use exav_unpack::{detect, extract, Budget, Format, Limits};

fn fixtures() -> Vec<std::path::PathBuf> {
    let dir = format!("{}/tests/fixtures/onenote", env!("CARGO_MANIFEST_DIR"));
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {dir}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "one").unwrap_or(false))
        .collect();
    out.sort();
    out
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
    for path in &files {
        let data = std::fs::read(path).unwrap();
        // All samples are genuine OneNote sections → must be detected.
        assert_eq!(
            detect(&data),
            Some(Format::OneNote),
            "not detected as OneNote: {}",
            path.display()
        );
        // Extraction must complete without panicking on real (hostile) input.
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::OneNote, &data, &mut budget)
            .unwrap_or_else(|e| panic!("extract {}: {}", path.display(), e.reason));
        total_members += entries.len();
    }
    // At least one real sample must yield an embedded member (these droppers
    // carry their payload as a FileDataStoreObject).
    assert!(
        total_members >= 1,
        "expected >=1 embedded member across the real samples, got {total_members}"
    );
}
