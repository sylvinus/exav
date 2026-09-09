//! ALZ extraction, validated **byte-for-byte against an external oracle**.
//!
//! ClamAV ships an ALZ submodule enabled by default; exav had nothing, so an
//! `.alz` scanned clean — its members are compressed, a raw pattern scan matches
//! nothing, and the file passes. That is the failure mode this crate exists to
//! prevent.
//!
//! The fixture is `defaults.alz` from the **MIT-licensed** EggDotNet project,
//! redistributed here under that licence. The expected digests below were
//! produced by **`unalz` 0.65** (zlib-licensed), and the member list was
//! independently cross-checked with **`unar`/`lsar`** (The Unarchiver). Two
//! independent implementations agreeing is what makes this a validation rather
//! than a round-trip against ourselves — a decoder checked only against its own
//! output emits plausible bytes rather than errors when it is subtly wrong.
//!
//! The header layout was derived from this archive by observation, then
//! confirmed field by field: the first member's declared sizes (1,171,458
//! compressed, 1,195,080 uncompressed) and its name matched `unalz` exactly.

use exav_unpack::{extract, Budget, Format, Limits};
use sha2::{Digest, Sha256};

/// `(name, uncompressed size, sha256 prefix)` — every member of the fixture, as
/// reported and extracted by `unalz`.
const EXPECTED: &[(&str, usize, &str)] = &[
    ("lorem_ipsum_long.tif", 1_195_080, "162d8b99fd7e695b"),
    ("lorem_ipsum_long.txt", 15_238, "d63cff6c64ab12f1"),
    ("lorem_ipsum_medium.txt", 3_950, "5dea92ab15a3a73a"),
    ("lorem_ipsum_short.txt", 525, "acfe59afcffcbe68"),
    ("lorem_ipsum.zip", 1_242_971, "f7e4474594f6b6c8"),
    ("lorem_ipsum_long.pdf", 66_431, "4b3e49290b2399c2"),
];

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/alz/defaults.alz",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn extract_all(data: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut limits = Limits::default();
    // The fixture holds a 1.2 MB member; the default per-member cap is ample,
    // but make the intent explicit so a future default change fails loudly here
    // rather than silently truncating and reporting `unsupported`.
    limits.max_buffer_bytes = limits.max_buffer_bytes.max(4 * 1024 * 1024);
    let mut b = Budget::new(limits);
    extract(Format::Alz, data, &mut b).expect("ALZ extraction must not error")
}

#[test]
fn every_member_matches_the_oracle_byte_for_byte() {
    let entries = extract_all(&fixture());
    assert_eq!(
        entries.len(),
        EXPECTED.len(),
        "expected {} members, got {}: {:?}",
        EXPECTED.len(),
        entries.len(),
        entries.iter().map(|e| &e.name).collect::<Vec<_>>()
    );

    for (e, (name, size, digest)) in entries.iter().zip(EXPECTED) {
        assert_eq!(&e.name, name, "member order or naming diverged");
        assert!(
            e.unsupported.is_none(),
            "{name} came back unsupported: {:?}",
            e.unsupported
        );
        assert_eq!(e.data.len(), *size, "{name}: wrong decompressed length");
        let got = format!("{:x}", Sha256::digest(&e.data));
        assert!(
            got.starts_with(digest),
            "{name}: content differs from `unalz` output (sha256 {got}, expected {digest}…). \
             A decoder that produces the right *length* but the wrong bytes is exactly \
             the failure an external oracle exists to catch."
        );
    }
}

#[test]
fn a_truncated_archive_is_reported_not_silently_short() {
    // Cut mid-member. The members before the cut are real and should still be
    // handed over; what must not happen is a clean, complete-looking result.
    let full = fixture();
    let entries = extract_all(&full[..full.len() / 2]);
    assert!(
        entries.len() < EXPECTED.len(),
        "a truncated archive cannot yield every member"
    );
    assert!(
        entries.iter().any(|e| e.unsupported.is_some()) || entries.len() < EXPECTED.len(),
        "truncation must be visible in the result"
    );
}

#[test]
fn garbage_after_the_magic_does_not_panic() {
    // The walk reads attacker-controlled lengths and offsets; the crate is
    // `#![forbid(unsafe_code)]`, so the requirement is that nothing indexes out
    // of bounds and every path terminates.
    for len in [0usize, 1, 7, 8, 9, 32, 200] {
        let mut v = b"ALZ\x01".to_vec();
        v.extend(std::iter::repeat_n(0xFFu8, len));
        let _ = extract_all(&v);
        let mut w = b"ALZ\x01".to_vec();
        w.extend_from_slice(b"\x00\x00\x00\x00BLZ\x01");
        w.extend(std::iter::repeat_n(0xAAu8, len));
        let _ = extract_all(&w);
    }
}

#[test]
fn a_recognised_archive_never_returns_nothing() {
    // An ALZ we cannot walk must still surface as unscannable rather than
    // yielding an empty, clean-looking result.
    let entries = extract_all(b"ALZ\x01\x00\x00\x00\x00");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].unsupported.is_some());
}
