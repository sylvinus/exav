//! The dictionary size an XZ stream declares — ClamAV's
//! `Heuristics.XZ.DicSizeLimit`, which has no flag to turn it off.
//!
//! This is a decompression-bomb signal that costs nothing to check: the declared
//! dictionary is memory a decoder must commit *before* producing a single byte,
//! so a stream declaring 4 GiB is expensive even when it decodes to nothing. A
//! size check on the output cannot catch it, because the allocation happens
//! first.
//!
//! The parser must be exact in both directions. Reporting `None` on anything it
//! does not fully understand is deliberate: a guessed dictionary size would
//! either invent alerts on ordinary archives or miss the ones that matter.

use exav_unpack::{xz_declared_dict_size, XZ_MAX_DICT};

/// Build an XZ stream header plus one block header declaring an LZMA2 filter
/// with dictionary-size property `prop`. The body is irrelevant — the whole
/// point is that this is readable before any decoding happens.
fn xz_with_dict_prop(prop: u8) -> Vec<u8> {
    let mut v = b"\xfd7zXZ\x00".to_vec();
    v.extend_from_slice(&[0x00, 0x00]); // stream flags
    v.extend_from_slice(&[0u8; 4]); // header CRC32 (not checked here)

    // Block header: size/4, flags (1 filter, no size fields), then the chain.
    let mut hdr = vec![
        0x01, // block flags: filter count 1, no compressed/uncompressed sizes
        0x21, // filter id: LZMA2
        0x01, // property length
        prop, // dictionary-size property
    ];
    // Pad to a multiple of 4 and prepend the size byte.
    while (hdr.len() + 1) % 4 != 0 {
        hdr.push(0);
    }
    let mut block = vec![((hdr.len() + 1) / 4) as u8];
    block.extend_from_slice(&hdr);
    v.extend_from_slice(&block);
    v.extend_from_slice(&[0u8; 16]); // body stand-in
    v
}

#[test]
fn a_modest_dictionary_is_read_and_accepted() {
    // The encoding is `(2 | (prop & 1)) << (prop / 2 + 11)`: property 0 is
    // 4 KiB, 20 is 4 MiB, 21 is 6 MiB. Spot-check the even, odd and smallest
    // cases so a sign or shift error cannot hide.
    for (prop, want) in [(0u8, 4096u64), (20, 4 * 1024 * 1024), (21, 6 * 1024 * 1024)] {
        let got = xz_declared_dict_size(&xz_with_dict_prop(prop));
        assert_eq!(got, Some(want), "property {prop} should decode to {want}");
        assert!(
            want <= XZ_MAX_DICT,
            "this fixture must stay under the cap or the test proves nothing"
        );
    }
}

#[test]
fn the_maximum_declaration_is_over_the_cap() {
    // 40 is the largest legal property and means 4 GiB — the shape that makes
    // this worth checking at all.
    let got = xz_declared_dict_size(&xz_with_dict_prop(40)).expect("must parse");
    assert_eq!(got, 4 * 1024 * 1024 * 1024, "property 40 is exactly 4 GiB");
    assert!(
        got > XZ_MAX_DICT,
        "a 4 GiB declaration must exceed exav's allocation cap; got {got}"
    );
}

#[test]
fn an_illegal_property_is_not_guessed_at() {
    // Above 40 is not a valid dictionary encoding. Returning `None` keeps a
    // malformed stream from being reported as a bomb.
    assert_eq!(xz_declared_dict_size(&xz_with_dict_prop(41)), None);
    assert_eq!(xz_declared_dict_size(&xz_with_dict_prop(255)), None);
}

#[test]
fn non_xz_input_reports_nothing() {
    assert_eq!(xz_declared_dict_size(b""), None);
    assert_eq!(xz_declared_dict_size(b"PK\x03\x04 not xz at all"), None);
    // Correct magic, truncated before the block header.
    assert_eq!(xz_declared_dict_size(b"\xfd7zXZ\x00\x00\x00"), None);
}

#[test]
fn a_real_xz_stream_declares_a_sane_dictionary() {
    // Produced by GNU `xz -9` — a genuine stream from an external encoder, not a
    // hand-built header. `-9` is the largest ordinary preset, so if any honest
    // compressor were going to trip the cap it would be this one.
    let path = format!(
        "{}/tests/fixtures/real_xz_stream.xz",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let dict = xz_declared_dict_size(&data)
        .expect("a real xz stream must be parseable, or the parser is too strict");
    assert!(
        dict <= XZ_MAX_DICT,
        "`xz -9` declared {dict}, above exav's cap — the cap or the parser is wrong"
    );
    assert!(
        dict >= 4096,
        "a real stream should declare a real dictionary"
    );
}
