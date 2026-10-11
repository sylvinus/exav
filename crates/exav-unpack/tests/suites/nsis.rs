//! NSIS installer extraction: real-sample robustness + synthetic-payload recovery.
use exav_unpack::{detect, extract, Budget, Format, Limits};

/// A real NSIS installer (PE stub + NSIS firstheader + compressed data block).
/// Its blocks use NSIS's modified bzip2, and every one of them decodes. It is
/// real malware, so it is **gitignored (not committed)**, kept locally in an
/// AES ZIP (`../README.md`); the tests skip when it's absent (fresh clone /
/// CI). sha256 provenance is in `fixtures/nsis/README.md`.
fn real_nsis() -> Option<Vec<u8>> {
    super::real_sample("nsis/real-malware-modbzip2.exe")
}

#[test]
fn real_sample_is_detected_as_nsis() {
    let Some(data) = real_nsis() else { return };
    assert_eq!(detect(&data), Some(Format::Nsis));
}

#[test]
fn real_sample_decodes_every_block() {
    let Some(data) = real_nsis() else { return };
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Nsis, &data, &mut budget).expect("must not fail the scan");
    assert!(!entries.is_empty(), "expected members");
    assert!(
        entries.iter().all(|e| e.unsupported.is_none()),
        "every block decodes: {:?}",
        entries
            .iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn synthetic_deflate_block_recovers_marker() {
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;

    // Build a minimal non-solid NSIS: MZ stub + firstheader + one raw-deflate
    // block carrying MALWARETEST.
    let sig: [u8; 16] = [
        0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's',
        b't',
    ];
    let payload = b"MALWARETEST hidden in an NSIS deflate block";
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(payload).unwrap();
    let deflate = enc.finish().unwrap();

    let mut blob = Vec::new();
    blob.extend_from_slice(b"MZ");
    blob.extend_from_slice(&[0u8; 62]);
    blob.extend_from_slice(&0u32.to_le_bytes()); // firstheader flags
    blob.extend_from_slice(&sig); // siginfo
    blob.extend_from_slice(&0u32.to_le_bytes()); // header_size

    // archive_size: from the firstheader through the CRC-32 after the data.
    blob.extend_from_slice(&((0x1c + 4 + deflate.len() + 4) as u32).to_le_bytes());
    let size_word = (deflate.len() as u32) | 0x8000_0000; // compressed block
    blob.extend_from_slice(&size_word.to_le_bytes());
    blob.extend_from_slice(&deflate);
    blob.extend_from_slice(&0u32.to_le_bytes()); // CRC-32

    assert_eq!(detect(&blob), Some(Format::Nsis));
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Nsis, &blob, &mut budget).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.data.windows(11).any(|w| w == b"MALWARETEST")),
        "MALWARETEST must be recovered"
    );
}

#[test]
fn truncated_and_garbage_do_not_panic() {
    let mut budget = Budget::new(Limits::default());

    // Truncated real sample (header present, data block cut short) — only when
    // the gitignored sample is present locally.
    if let Some(data) = real_nsis() {
        let truncated = &data[..data.len() / 3];
        let _ = extract(Format::Nsis, &truncated, &mut budget);
    }

    // Signature with no valid firstheader following.
    let mut junk = b"MZ".to_vec();
    junk.extend_from_slice(&[0u8; 4]);
    junk.extend_from_slice(&[
        0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's',
        b't',
    ]);
    let mut budget = Budget::new(Limits::default());
    let _ = extract(Format::Nsis, &junk, &mut budget);

    // Pure garbage that isn't NSIS at all.
    let mut budget = Budget::new(Limits::default());
    let entries = extract(Format::Nsis, b"not an nsis file at all", &mut budget).unwrap();
    assert!(entries.is_empty());
}
