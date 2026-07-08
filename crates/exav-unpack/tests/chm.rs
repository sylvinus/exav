//! CHM (Microsoft Compiled HTML Help) detection and extraction tests.
//!
//! * `benign-lzx.chm` is a **committed** fixture: a small, original CC0 /
//!   public-domain help page compiled to a genuine LZX-compressed CHM (built
//!   with `chmcmd`; see `tests/fixtures/chm/README.md`). It carries no payload
//!   and is the always-on oracle for the **LZX decode path** — the one piece of
//!   coverage that can't be synthesised (exav ships an LZX *decoder*, not an
//!   encoder).
//! * The `real-malware-*.chm` samples are real malware and are therefore
//!   **gitignored, not committed** (sha256 provenance in that dir's README).
//!   The tests read them at runtime and **skip when absent** (a fresh clone /
//!   CI), adding extra real-world hostile-input robustness for local runs.

#![cfg(feature = "chm")]

use exav_unpack::{detect, extract, Budget, Format, Limits};

/// The committed, benign LZX oracle. Must always be present.
const BENIGN_LZX: &str = "benign-lzx.chm";

/// Real-malware samples (gitignored; tests skip them when absent).
const REAL_SAMPLES: &[&str] = &["real-malware-lzx-1.chm", "real-malware-lzx-2.chm"];

fn read_fixture(name: &str) -> Option<Vec<u8>> {
    let p = format!("{}/tests/fixtures/chm/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).ok()
}

/// Always-on: the committed benign CHM is detected, and its LZX-compressed HTML
/// topic decodes byte-for-byte (proving the ITSF/ITSP + ResetTable + LZX path,
/// not just the raw directory). This is the real decode-correctness oracle.
#[test]
fn benign_lzx_detects_and_decodes() {
    let data = read_fixture(BENIGN_LZX).expect("benign-lzx.chm must be committed");
    assert_eq!(detect(&data), Some(Format::Chm));

    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Chm, &data, &mut budget).expect("extract");
    let joined: Vec<u8> = entries
        .iter()
        .flat_map(|e| e.data.iter().copied())
        .collect();
    // The marker lives inside the LZX-compressed content section, so finding it
    // proves the LZX decompressor reconstructed the topic.
    assert!(
        joined.windows(11).any(|w| w == b"EXAV-LZX-OK"),
        "LZX-decoded marker not recovered"
    );
    assert!(
        joined.windows(5).any(|w| w.eq_ignore_ascii_case(b"<html")),
        "no decompressed HTML markup found"
    );
}

/// The benign CHM, and any locally-present real samples, extract into at least
/// one member and never panic. (Real samples add real-world-input robustness.)
#[test]
fn extracts_members_without_panicking() {
    let mut names: Vec<&str> = vec![BENIGN_LZX];
    names.extend_from_slice(REAL_SAMPLES);
    for name in names {
        let Some(data) = read_fixture(name) else {
            continue;
        };
        let mut budget = Budget::new(Limits::default());
        let entries =
            extract(Format::Chm, &data, &mut budget).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!entries.is_empty(), "{name}: expected >=1 member, got none");
        // At least one member carries decoded bytes OR is flagged unsupported —
        // never a silent empty-but-clean member set.
        let progress = entries
            .iter()
            .any(|e| !e.data.is_empty() || e.unsupported.is_some());
        assert!(progress, "{name}: no decoded or unsupported members");
    }
}

/// Truncating a CHM to just its ITSF magic (directory gone) must return cleanly,
/// never panic. Exercised on the benign fixture plus any local real samples.
#[test]
fn truncated_head_does_not_panic() {
    let mut names: Vec<&str> = vec![BENIGN_LZX];
    names.extend_from_slice(REAL_SAMPLES);
    for name in names {
        let Some(data) = read_fixture(name) else {
            continue;
        };
        let head = &data[..64.min(data.len())];
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Chm, head, &mut budget).unwrap();
        assert!(entries.is_empty(), "{name}: truncated head yielded members");
    }
}

#[test]
fn random_bytes_after_itsf_do_not_panic() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"ITSF");
    for i in 0..8192u32 {
        blob.push((i.wrapping_mul(2654435761) >> 11) as u8);
    }
    let mut budget = Budget::new(Limits::default());
    // Must not panic; a bogus directory just yields no members.
    let _ = extract(Format::Chm, &blob, &mut budget).unwrap();
}
