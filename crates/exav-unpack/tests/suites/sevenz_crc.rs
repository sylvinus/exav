//! A 7z member is checked against the CRC the header gives it as it ends. The
//! folder has decoded in full, so a mismatch is not damage: the bytes are
//! handed over and the error that follows them is the checksum's
//! ([`exav_unpack::decode_error_hides_content`] is false for it).
//!
//! * `copy.7z`: one stored file, `readme.txt` (17 bytes), packed from 32.
//! * `lzma2_solid.7z`: four files in one LZMA2 folder; `random.bin` (10 KiB of
//!   random bytes) is the first, and LZMA2 stores random data as it is, so
//!   a byte changed in it decodes and fails only the CRC.

use exav_unpack::{Budget, Format, Limits, Member, walk};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/7z/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// What the walk gave for a member: its bytes, and how reading them ended.
struct Got {
    name: String,
    data: Vec<u8>,
    failed: Option<std::io::Error>,
    unsupported: Option<&'static str>,
}

fn walked(blob: &[u8]) -> Vec<Got> {
    let mut budget = Budget::new(Limits::default());
    let mut out = Vec::new();
    walk(
        Format::SevenZip,
        &blob,
        &mut budget,
        &mut |meta, content, _| {
            let (data, failed) = match content {
                Some(Member::Stream(r)) => {
                    let mut b = Vec::new();
                    let failed = r.read_to_end(&mut b).err();
                    (b, failed)
                }
                Some(Member::Bytes(b)) => (b, None),
                None => (Vec::new(), None),
            };
            out.push(Got {
                name: meta.name.clone(),
                data,
                failed,
                unsupported: meta.unsupported,
            });
            None::<()>
        },
    )
    .unwrap();
    out
}

/// The error is the checksum's: the member was decoded in full.
fn is_checksum_error(m: &Got) -> bool {
    m.failed.as_ref().is_some_and(|e| {
        e.kind() == std::io::ErrorKind::InvalidData && !exav_unpack::decode_error_hides_content(e)
    })
}

#[test]
fn members_that_match_their_crcs_read_to_their_end() {
    for name in ["copy.7z", "lzma2_solid.7z"] {
        let got = walked(&fixture(name));
        assert!(!got.is_empty(), "{name}");
        for m in &got {
            assert!(m.failed.is_none(), "{name}: {} {:?}", m.name, m.failed);
            assert!(m.unsupported.is_none(), "{name}: {}", m.name);
        }
    }
}

#[test]
fn a_stored_member_that_does_not_match_its_crc_fails_at_its_end() {
    let mut blob = fixture("copy.7z");
    blob[32 + 3] ^= 0x20;
    let got = walked(&blob);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data.len(), 17, "the bytes are given");
    assert!(is_checksum_error(&got[0]), "{:?}", got[0].failed);
}

/// In a solid folder only the member that fails its CRC fails, and the ones
/// after it are read.
#[test]
fn only_the_member_that_does_not_match_its_crc_fails() {
    let clean = walked(&fixture("lzma2_solid.7z"));
    let mut blob = fixture("lzma2_solid.7z");
    // Inside the first chunk of random.bin, past its 3-byte chunk header.
    blob[32 + 100] ^= 0x01;
    let got = walked(&blob);
    assert_eq!(got.len(), clean.len());
    for (m, c) in got.iter().zip(&clean) {
        assert_eq!(m.name, c.name);
        assert_eq!(m.data.len(), c.data.len(), "{}", m.name);
        if m.name.ends_with("random.bin") {
            assert!(is_checksum_error(m), "{}: {:?}", m.name, m.failed);
            assert_ne!(m.data, c.data, "{}", m.name);
        } else {
            assert!(m.failed.is_none(), "{}: {:?}", m.name, m.failed);
            assert_eq!(m.data, c.data, "{}", m.name);
        }
    }
}
