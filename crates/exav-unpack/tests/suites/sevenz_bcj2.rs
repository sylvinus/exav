//! 7z BCJ2: the four-input x86 branch converter.
//!
//! 7-Zip picks BCJ2 automatically for executables at `-mx=9`, so "a 7z of an
//! .exe at maximum compression" is an entirely ordinary thing for an attacker to
//! produce.
//!
//! The fixtures were produced by **official 7-Zip 25.01**, and the expected
//! digests below are `7zz x` output, not this crate's. A decoder validated
//! against an encoder written beside it can agree on a shared misreading; these
//! digests come from the reference implementation, so a mismatch is exav's.
//!
//! Regenerate with:
//! ```sh
//! 7zz a -t7z -mx=9 -mf=BCJ2 bcj2.7z sample.bin eicar.txt
//! ```

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

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
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 32 * 1024 * 1024;
    limits.max_extracted_bytes = 64 * 1024 * 1024;
    let mut b = Budget::new(limits);
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
        "the x86 binary must decode identically to `7zz x`: a BCJ2 filter that \
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

/// `bcj2_window.7z`: an x86-like `code.bin` of 300,013 bytes and
/// `eicar.txt` in one BCJ2 folder whose LZMA coders have a 64 KiB dictionary,
/// made with p7zip 16.02:
/// ```sh
/// 7z a -t7z -m0=BCJ2 -m1=LZMA:d=64k -m2=LZMA:d=64k -m3=LZMA:d=64k \
///   -mb0:1 -mb0s1:2 -mb0s2:3 bcj2_window.7z code.bin eicar.txt
/// ```
/// and `sha256sum` of what `7z x` gives.
const WINDOW_CODE_SHA256: &str = "5842d1aabbc4c4bb4ecac596b66d92c1cbcdbb0fdd9f9d3b35956a8cc47ecc38";

/// A BCJ2 folder whose output is larger than the buffer limit, off a source
/// that is not in memory, is decoded as it is read: its four streams each
/// from their place in the archive, the members as 7-Zip gives them, the last
/// one included. Only the LZMA windows are held.
#[test]
fn a_bcj2_folder_past_the_buffer_limit_is_decoded_as_it_is_read() {
    use exav_unpack::Member;
    let blob = fixture("bcj2_window.7z");
    let cache = exav_unpack::source::BlockCache::with_sizes(
        std::io::Cursor::new(blob.clone()),
        4096,
        64 * 1024,
    )
    .unwrap();
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 128 * 1024;
    let mut b = Budget::new(limits);
    let mut got = Vec::new();
    exav_unpack::walk(Format::SevenZip, &cache, &mut b, &mut |meta, content, _| {
        assert!(
            meta.unsupported.is_none(),
            "{}: {:?}",
            meta.name,
            meta.unsupported
        );
        let mut data = Vec::new();
        match content {
            Some(Member::Stream(r)) => {
                r.read_to_end(&mut data).unwrap();
            }
            Some(Member::Bytes(d)) => data = d,
            #[allow(unreachable_patterns)]
            _ => {}
        }
        got.push((meta.name.clone(), sha256_hex(&data)));
        None::<()>
    })
    .unwrap();
    let digest = |n: &str| {
        got.iter()
            .find(|(name, _)| name.ends_with(n))
            .map(|(_, d)| d.as_str())
            .unwrap_or_else(|| panic!("no {n}: {got:?}"))
    };
    assert_eq!(digest("code.bin"), WINDOW_CODE_SHA256);
    assert_eq!(digest("eicar.txt"), EICAR_SHA256);
}

/// The same folder under a buffer limit smaller than its 64 KiB dictionaries:
/// the windows cannot be held, so the folder is a limit reached and its
/// members are left out. Decoded with smaller windows, a valid stream fails at
/// the first match that reaches further back, and reads as damaged.
#[test]
fn a_folder_whose_dictionary_is_over_the_buffer_limit_is_a_limit() {
    let blob = fixture("bcj2_window.7z");
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 32 * 1024;
    let mut b = Budget::new(limits);
    let mut seen = Vec::new();
    let walked = exav_unpack::walk(
        Format::SevenZip,
        &blob.as_slice(),
        &mut b,
        &mut |meta, content, _| {
            seen.push((meta.name.clone(), content.is_some()));
            None::<()>
        },
    );
    let hit = walked.expect_err("the folder is refused");
    assert!(!hit.is_corrupt(), "{}", hit.reason);
    let said = &hit.reason;
    assert!(
        said.contains("LZMA dictionary is over the buffer limit"),
        "{said}"
    );
    assert!(seen.iter().all(|(_, decoded)| !decoded), "{seen:?}");
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
