//! A file the reader cannot parse is damaged (`UNSCANNABLE`), not over a limit
//! (`LIMITS-EXCEEDED`): the verdict says whether a bigger budget would help.

use exav_unpack::{Budget, Format, Limits, extract};

fn refusal(format: Format, data: &[u8]) -> exav_unpack::LimitHit {
    let mut budget = Budget::new(Limits::default());
    extract(format, &data, &mut budget).expect_err("the reader refuses it")
}

#[test]
fn junk_in_a_reader_s_format_is_damage() {
    let mut lha_level_9 = vec![0x20u8, 0];
    lha_level_9.extend_from_slice(b"-lh5-");
    lha_level_9.resize(40, 0);
    lha_level_9[20] = 9;
    // xar: the 28-byte header, a table of contents of 8 bytes that is not
    // zlib, and the length it should have.
    let mut xar = b"xar!".to_vec();
    xar.extend_from_slice(&28u16.to_be_bytes());
    xar.extend_from_slice(&1u16.to_be_bytes());
    xar.extend_from_slice(&8u64.to_be_bytes());
    xar.extend_from_slice(&100u64.to_be_bytes());
    xar.extend_from_slice(&0u32.to_be_bytes());
    xar.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    let cases: [(&str, Format, &[u8]); 6] = [
        ("ar", Format::Ar, b"this is not an ar archive at all"),
        ("cpio", Format::Cpio, b"this is not a cpio archive at all"),
        ("email", Format::Email, b""),
        ("lha", Format::Lha, &lha_level_9),
        ("ole", Format::Ole, b"this is not a compound file at all"),
        ("xar", Format::Xar, &xar),
    ];
    let mut limits = Vec::new();
    for (what, format, data) in cases {
        let e = refusal(format, data);
        if !e.is_corrupt() {
            limits.push(format!("{what}: {}", e.reason));
        }
    }
    assert!(limits.is_empty(), "reported as limits: {limits:#?}");
}
