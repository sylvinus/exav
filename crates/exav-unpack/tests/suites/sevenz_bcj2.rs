//! 7z BCJ2 — the four-input x86 branch converter.
//!
//! 7-Zip picks BCJ2 automatically for executables at `-mx=9`, so "a 7z of an
//! .exe at maximum compression" is an entirely ordinary thing for an attacker to
//! produce.
//!
//! The fixtures were produced by **official 7-Zip 25.01**, and the expected
//! digests below are `7zz x` output — not this crate's. A decoder validated
//! against an encoder written beside it can agree on a shared misreading; these
//! digests come from the reference implementation, so a mismatch is exav's.
//!
//! Regenerate with:
//! ```sh
//! 7zz a -t7z -mx=9 -mf=BCJ2 bcj2.7z sample.bin eicar.txt
//! ```

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of the members as extracted by `7zz x`.
const SAMPLE_SHA256: &str = "fb051a6c58961fb6aec758acf50d7d0375eecff740d0706388092829e3fb7a41";
const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/sevenz/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits {
        max_buffer_bytes: 32 * 1024 * 1024,
        max_extracted_bytes: 64 * 1024 * 1024,
        ..Limits::default()
    });
    let _ = extract_each(
        Format::SevenZip,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

#[test]
fn bcj2_members_match_7zip_byte_for_byte() {
    let e = members(&fixture("bcj2.7z"));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "BCJ2 must decode, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );

    let sample = e
        .iter()
        .find(|x| x.name.ends_with("sample.bin"))
        .expect("sample.bin must be extracted");
    assert_eq!(
        sha256_hex(&sample.data),
        SAMPLE_SHA256,
        "the x86 binary must decode identically to `7zz x` — a BCJ2 filter that \
         is subtly wrong still produces plausible-looking output"
    );

    let eicar = e
        .iter()
        .find(|x| x.name.ends_with("eicar.txt"))
        .expect("eicar.txt must be extracted");
    assert_eq!(sha256_hex(&eicar.data), EICAR_SHA256);
}

#[test]
fn a_second_bcj2_archive_also_decodes() {
    // A different x86 binary, so the test does not rest on one branch-density
    // profile.
    let e = members(&fixture("bcj2_small.7z"));
    assert!(
        e.iter()
            .any(|x| x.unsupported.is_none() && !x.data.is_empty()),
        "a second BCJ2 archive must decode, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_payload_inside_a_bcj2_archive_is_reachable() {
    let eicar = exav_unpack::eicar();
    let e = members(&fixture("bcj2.7z"));
    assert!(
        e.iter()
            .any(|x| x.data.windows(eicar.len()).any(|w| w == eicar)),
        "the payload must be reachable through a BCJ2 folder"
    );
}
