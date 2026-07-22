//! Coverage against real packed samples, when they are present.
//!
//! The technique tests pin *behaviour* with synthetic stubs; this one measures
//! *coverage* against binaries produced by the actual packers. The samples are
//! ordinary Windows utilities packed with each tool — not malware — fetched by
//! `scripts/fetch-packed-pe.py` into `corpus/packers/`, which is gitignored.
//!
//! The whole suite is skipped when that directory is absent, so a clean
//! checkout still passes. Where it runs, it is a ratchet: the packers listed as
//! fully working must unpack *every* sample, and the set as a whole must stay
//! above a floor. Both numbers are what the emulator does today, so any change
//! that loses a packer fails here rather than in a campaign three weeks later.
//!
//! Marked `#[ignore]`: running 69 stubs to completion takes minutes, which does
//! not belong in a suite people run on every edit. Run it after touching the
//! emulator:
//!
//! ```text
//! cargo test --release -p exav-unpack --test all -- --ignored pe_emulation_corpus
//! ```

use exav_unpack::{extract, Budget, Format, Limits};
use std::path::{Path, PathBuf};

/// Packers where every sample is expected to yield a reconstructed image.
const MUST_UNPACK: &[&str] = &[
    "ASPack",
    "BeRoEXEPacker",
    "EXpressor",
    "FSG",
    "MEW",
    "MPRESS",
    "Molebox",
    "NSPack",
    "Neolite",
    "PECompact",
    "Packman",
    "RLPack",
    "UPX",
    "WinUpack",
    "Yoda-Crypter",
];

/// Fraction of *all* samples that must come back as a complete image. Below the
/// 78% measured over 276 samples from 23 packers, to leave room for the sample
/// set changing without turning this into noise.
///
/// The per-packer list above is the sharper check: those packers work on every
/// sample, so one failure there is a regression, where a percentage point of
/// the total is drift.
const FLOOR: f64 = 0.70;

fn corpus() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/packers");
    dir.is_dir().then_some(dir)
}

/// Run one sample through the unpacker exactly as the scanner would, returning
/// the largest member it produced.
///
/// Size is the check that matters, not merely "a member came back". A packed
/// file decompresses to *more* than it occupies on disk, so a recovered image
/// smaller than the input is a run that stopped part-way — which is exactly how
/// a too-eager entry-point heuristic fails: it reports success while handing
/// back a half-decompressed image.
fn largest_recovered(file: &[u8]) -> usize {
    let mut b = Budget::new(Limits {
        max_extracted_bytes: 1 << 30,
        max_buffer_bytes: 1 << 30,
        ..Default::default()
    });
    match extract(Format::PePacked, file, &mut b) {
        Ok(entries) => entries.iter().map(|e| e.data.len()).max().unwrap_or(0),
        Err(_) => 0,
    }
}

#[test]
#[ignore = "minutes of emulation; run explicitly after touching the emulator"]
fn real_packed_samples_still_unpack() {
    let Some(root) = corpus() else {
        eprintln!("corpus/packers absent — run scripts/fetch-packed-pe.py to enable this test");
        return;
    };
    let mut total = 0usize;
    let mut recovered = 0usize;
    let mut regressions: Vec<String> = Vec::new();

    let mut packers: Vec<_> = std::fs::read_dir(&root)
        .expect("read corpus/packers")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    packers.sort_by_key(|e| e.file_name());

    for packer in packers {
        let name = packer.file_name().to_string_lossy().to_string();
        let must = MUST_UNPACK.contains(&name.as_str());
        for sample in std::fs::read_dir(packer.path()).expect("read packer dir") {
            let Ok(sample) = sample else { continue };
            let Ok(data) = std::fs::read(sample.path()) else {
                continue;
            };
            if data.len() < 0x40 || &data[..2] != b"MZ" {
                continue;
            }
            total += 1;
            let biggest = largest_recovered(&data);
            if biggest >= data.len() {
                recovered += 1;
            }
            if must && biggest < data.len() {
                regressions.push(format!(
                    "{name}/{} (recovered {biggest} bytes from {})",
                    sample.file_name().to_string_lossy(),
                    data.len()
                ));
            }
        }
    }

    assert!(total > 0, "corpus/packers exists but holds no PE samples");
    assert!(
        regressions.is_empty(),
        "packers that used to give back a full image no longer do: {regressions:?}"
    );
    let ratio = recovered as f64 / total as f64;
    assert!(
        ratio >= FLOOR,
        "only {recovered}/{total} packed samples yielded anything ({:.0}%), below the {:.0}% floor",
        ratio * 100.0,
        FLOOR * 100.0
    );
}
