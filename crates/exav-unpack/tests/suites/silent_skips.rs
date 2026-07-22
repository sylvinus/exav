//! Regressions for members that existed but produced nothing.
//!
//! Each case here was a `continue` that dropped a member the container's own
//! directory names. All are the same class — the bytes are in the file, exav
//! failed to read them, so the result must say so rather than come back clean.
//! `CONTRIBUTING.md` sets out the classification these are judged against.
//!
//! The counterpart matters just as much: category **(d)**, where the container
//! declares bytes the file does not contain, must stay quiet. `ordinary_*` tests
//! elsewhere pin that side.

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

/// Every member `extract_each` produces, as `(name, unsupported-reason)`.
/// `extract` is not usable here: it discards already-emitted entries when the
/// walk ends in `Err`, so a member reported before a later failure disappears.
fn members(fmt: Format, data: &[u8]) -> Vec<(String, Option<&'static str>)> {
    let mut budget = Budget::new(Limits::default());
    let mut out = Vec::new();
    let _ = extract_each::<()>(fmt, data, &mut budget, &mut |e: Entry, _: &mut Budget| {
        out.push((e.name, e.unsupported));
        None
    });
    out
}

/// A XAR whose TOC names a member whose heap block is not a valid zlib stream.
/// The bytes are present; only the codec fails.
#[cfg(feature = "xar")]
#[test]
fn a_xar_member_that_will_not_inflate_is_reported() {
    use std::io::Write;

    let toc = r#"<?xml version="1.0"?><xar><toc><file id="1"><name>payload.bin</name><type>file</type><data><offset>0</offset><size>64</size><length>16</length><encoding style="application/x-gzip"/></data></file></toc></xar>"#;
    let mut deflated = Vec::new();
    {
        let mut e = flate2::write::ZlibEncoder::new(&mut deflated, flate2::Compression::fast());
        e.write_all(toc.as_bytes()).unwrap();
        e.finish().unwrap();
    }

    let mut blob = Vec::new();
    blob.extend_from_slice(b"xar!");
    blob.extend_from_slice(&28u16.to_be_bytes()); // header size
    blob.extend_from_slice(&1u16.to_be_bytes()); // version
    blob.extend_from_slice(&(deflated.len() as u64).to_be_bytes()); // toc compressed
    blob.extend_from_slice(&(toc.len() as u64).to_be_bytes()); // toc uncompressed
    blob.extend_from_slice(&1u32.to_be_bytes()); // checksum alg
    blob.extend_from_slice(&deflated);
    // The heap: 16 bytes that are emphatically not a zlib stream.
    blob.extend_from_slice(&[0xFFu8; 16]);

    let m = members(Format::Xar, &blob);
    assert!(
        m.iter().any(|(n, u)| n == "payload.bin" && u.is_some()),
        "a member whose stream will not inflate must be reported, got {m:?}"
    );
}

// The two UDF sites (an unreadable directory body, an unreadable file extent)
// have no regression test here: a bare BEA01 descriptor is not enough for the
// walker to claim the image, and hand-forging a UDF ICB whose extents resolve to
// nothing is a fixture that would encode the bug's shape rather than the
// contract. They are covered by the `udf` suite's real-image digests instead.

/// A CAB whose directory names a member the folder's data never reaches. The
/// cabinet lists it, so it exists; a forward-only reader simply cannot get to
/// it, which is a gap to report rather than a member to forget.
#[cfg(feature = "cab")]
#[test]
fn a_cab_member_beyond_its_folder_data_is_reported() {
    // Built by hand: a single folder whose data blocks stop short of the second
    // file's declared uncompressed offset.
    let name_a = b"a.txt\0";
    let name_b = b"b.txt\0";
    let cffile_len = 16 + name_a.len() + 16 + name_b.len();
    let cfheader_len = 36;
    let cffolder_len = 8;
    let files_off = cfheader_len + cffolder_len;
    let data_off = files_off + cffile_len;

    let payload = b"hello";
    let mut blob = Vec::new();
    blob.extend_from_slice(b"MSCF");
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbCabinet (patched below)
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    blob.extend_from_slice(&(files_off as u32).to_le_bytes()); // coffFiles
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved3
    blob.push(3); // versionMinor
    blob.push(1); // versionMajor
    blob.extend_from_slice(&1u16.to_le_bytes()); // cFolders
    blob.extend_from_slice(&2u16.to_le_bytes()); // cFiles
    blob.extend_from_slice(&0u16.to_le_bytes()); // flags
    blob.extend_from_slice(&0u16.to_le_bytes()); // setID
    blob.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
                                                 // CFFOLDER
    blob.extend_from_slice(&(data_off as u32).to_le_bytes()); // coffCabStart
    blob.extend_from_slice(&1u16.to_le_bytes()); // cCFData
    blob.extend_from_slice(&0u16.to_le_bytes()); // typeCompress = none
                                                 // CFFILE a: offset 0, fits.
    blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // uoffFolderStart
    blob.extend_from_slice(&0u16.to_le_bytes()); // iFolder
    blob.extend_from_slice(&0u16.to_le_bytes()); // date
    blob.extend_from_slice(&0u16.to_le_bytes()); // time
    blob.extend_from_slice(&0u16.to_le_bytes()); // attribs
    blob.extend_from_slice(name_a);
    // CFFILE b: declared far past the end of the folder's only data block.
    blob.extend_from_slice(&8u32.to_le_bytes());
    blob.extend_from_slice(&100_000u32.to_le_bytes()); // uoffFolderStart
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(name_b);
    // CFDATA: one uncompressed block holding just `payload`.
    blob.extend_from_slice(&0u32.to_le_bytes()); // csum
    blob.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // cbData
    blob.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // cbUncomp
    blob.extend_from_slice(payload);
    let total = blob.len() as u32;
    blob[8..12].copy_from_slice(&total.to_le_bytes());

    // Asserted, not guarded: a fixture that stopped being recognised would turn
    // this into a test that cannot fail.
    assert_eq!(
        exav_unpack::detect(&blob),
        Some(Format::Cab),
        "the hand-built cabinet is no longer recognised, so this test proves nothing"
    );
    let m = members(Format::Cab, &blob);
    assert!(
        m.iter().any(|(n, _)| n == "b.txt"),
        "the unreachable member must still appear in the result: {m:?}"
    );
    assert!(
        m.iter().any(|(n, u)| n == "b.txt" && u.is_some()),
        "and it must carry a reason rather than read as empty: {m:?}"
    );
}
