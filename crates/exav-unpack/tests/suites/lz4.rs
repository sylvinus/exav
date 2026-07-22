//! LZ4 frames (`.lz4`).
//!
//! The expected digests are `lz4 -dc` output — the reference tool's, not this
//! crate's. Fixtures cover the frame variants the tool itself produces, because
//! the ones a decoder is most likely to get wrong are the ones it never sees:
//! linked blocks, the legacy frame, per-block checksums, and **concatenation**,
//! which is a one-command way to hide a payload behind a first frame.
//!
//! Regenerate with:
//! ```sh
//! lz4 -9 -c one.txt > one.lz4
//! lz4 -9 -BD -c one.txt > one_linked.lz4        # linked blocks
//! lz4 -9 -B4 --content-size -c one.txt > one_sized.lz4
//! lz4 -9 -BX -c one.txt > one_bcksum.lz4        # per-block checksums
//! lz4 -l -9 -c one.txt > one_legacy.lz4         # legacy frame
//! lz4 -1 -c eicar.com > eicar.lz4
//! cat one.lz4 eicar.lz4 > two_frames.lz4
//! ```

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of what `lz4 -dc` writes for each fixture.
const ONE: &str = "30c2abfccdf15a28990bae7bb0efa2444d82af3ce7053ff493956ef9612f775d";
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const BOTH: &str = "eaa51b48ad93";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/lz4/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn content(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let blob = fixture(name);
    let _ = extract_each(
        Format::Lz4,
        &blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            assert!(e.unsupported.is_none(), "{name}: {:?}", e.unsupported);
            out.extend_from_slice(&e.data);
            None::<()>
        },
    );
    out
}

#[test]
fn every_frame_variant_matches_the_reference_tool() {
    for name in [
        "one.lz4",
        "one_linked.lz4",
        "one_sized.lz4",
        "one_bcksum.lz4",
        "one_legacy.lz4",
    ] {
        assert_eq!(
            sha256_hex(&content(name)),
            ONE,
            "{name} must decode to what `lz4 -dc` produces"
        );
    }
    assert_eq!(sha256_hex(&content("eicar.lz4")), EICAR);
}

#[test]
fn a_payload_hidden_behind_a_first_frame_is_still_reached() {
    // `lz4 -dc` on concatenated frames emits all of them. A decoder that stops
    // at the first end mark leaves everything after it unscanned while the file
    // still reports clean — and appending a frame is a single `cat`.
    let d = content("two_frames.lz4");
    assert_eq!(
        &sha256_hex(&d)[..12],
        BOTH,
        "both frames must be decoded, got {} bytes",
        d.len()
    );
    const EICAR_BYTES: &[u8] =
        br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
    assert!(
        d.windows(EICAR_BYTES.len()).any(|w| w == EICAR_BYTES),
        "the payload in the second frame must be reachable"
    );
}

#[test]
fn a_frame_is_recognised_from_its_magic() {
    assert_eq!(detect(&fixture("one.lz4")), Some(Format::Lz4));
    assert_eq!(detect(&fixture("one_legacy.lz4")), Some(Format::Lz4));
}

#[test]
fn a_truncated_frame_yields_what_it_can_without_panicking() {
    // Cutting a frame short leaves bytes that are really absent, not hidden.
    // What decoded before the cut is still content worth scanning.
    let full = fixture("one.lz4");
    for n in [16, 64, 512, full.len() / 2, full.len() - 1] {
        let mut b = Budget::new(Limits::default());
        let _ = extract_each(
            Format::Lz4,
            &full[..n],
            &mut b,
            &mut |_: Entry, _: &mut Budget| None::<()>,
        );
    }
}
