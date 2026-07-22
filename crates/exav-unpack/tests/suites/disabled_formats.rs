//! A container this build cannot open must still be *named*, not ignored.
//!
//! Runs only in a build with formats disabled, which is the only configuration
//! where there is anything to check: every other pass in the matrix has
//! `all-formats`.
//!
//! The failure this pins is detection sharing a feature gate with the extractor.
//! A disabled format would then be undetected rather than unopenable, the file
//! would get a raw pattern scan over its compressed bytes, match nothing, and
//! come back clean — the one outcome exav refuses.
#![cfg(not(feature = "all-formats"))]

use exav_unpack::{detect, extract, Budget, Limits};

/// `(what it is, a blob that sniffs as it)`. Magic only — enough for `detect`,
/// not a valid archive, which is deliberate: recognition must not need a
/// well-formed file.
fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = vec![
        ("ace", [&[0u8; 7][..], b"**ACE**", &[0; 32]].concat()),
        ("lz4", [&[0x04, 0x22, 0x4D, 0x18][..], &[0; 32]].concat()),
        ("lzw", b"\x1f\x9d\x90some compressed bytes".to_vec()),
        ("stuffit", b"SIT!and then some data".to_vec()),
        // VHDX's second region table sits at 192 KiB, so the sniff needs a file
        // at least that long.
        (
            "vhdx",
            [b"vhdxfile".as_slice(), &vec![0u8; 200 * 1024]].concat(),
        ),
        // Long enough for the 208-byte WIM header.
        ("wim", [b"MSWIM\0\0\0".as_slice(), &[0; 256]].concat()),
        // The version word is part of the sniff, so it has to be a real one.
        (
            "qcow2",
            [b"QFI\xfb\x00\x00\x00\x03".as_slice(), &[0; 128]].concat(),
        ),
        ("vmdk", [b"KDMV".as_slice(), &[0; 600]].concat()),
        ("alz", b"ALZ\x01some archive bytes".to_vec()),
        ("egg", b"EGGA\x01\x00some archive bytes".to_vec()),
        (
            "hwp3",
            b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05data".to_vec(),
        ),
    ];
    let mut vhd = vec![0u8; 1024];
    vhd[512..520].copy_from_slice(b"conectix");
    v.push(("vhd", vhd));
    let mut ntfs = vec![0u8; 512];
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    ntfs[11..13].copy_from_slice(&512u16.to_le_bytes());
    ntfs[510..512].copy_from_slice(&[0x55, 0xAA]);
    v.push(("ntfs", ntfs));
    v
}

#[test]
fn a_container_this_build_cannot_open_is_still_detected() {
    for (what, blob) in samples() {
        assert!(
            detect(&blob).is_some(),
            "{what}: went undetected, so it will get a raw pattern scan and read clean"
        );
    }
}

#[test]
fn extracting_it_reports_rather_than_yielding_nothing() {
    for (what, blob) in samples() {
        let Some(fmt) = detect(&blob) else { continue };
        let mut budget = Budget::new(Limits::default());
        let entries = extract(fmt, &blob, &mut budget)
            .unwrap_or_else(|e| panic!("{what}: extract errored: {e}"));
        assert!(
            !entries.is_empty(),
            "{what}: yielded no members — indistinguishable from an empty archive"
        );
        assert!(
            entries.iter().any(|e| e.unsupported.is_some()),
            "{what}: every member must carry a reason, got {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert!(
            entries.iter().all(|e| e.data.is_empty()),
            "{what}: no content may be invented for a format we cannot decode"
        );
    }
}

#[test]
fn ordinary_files_are_not_claimed() {
    // The sniffs are short; a false positive turns a text file into a spurious
    // UNSCANNABLE, which is its own kind of lie.
    for blob in [
        &b""[..],
        &b"just some ordinary text, nothing to see here\n"[..],
        &b"MZ\x90\x00\x03"[..],
        &b"\x7fELF\x02\x01\x01"[..],
        &b"{\"json\": true}"[..],
    ] {
        assert_eq!(
            exav_unpack::detect(blob),
            None,
            "claimed an ordinary file: {blob:x?}"
        );
    }
}
