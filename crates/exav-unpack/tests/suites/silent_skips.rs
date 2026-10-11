//! Regressions for members that existed but produced nothing.
//!
//! Each case here was a `continue` that dropped a member the container's own
//! directory names. All are the same class: the bytes are in the file, exav
//! failed to read them, so the result must say so rather than come back clean.
//! `CONTRIBUTING.md` sets out the classification these are judged against.
//!
//! The counterpart matters just as much: category **(d)**, where the container
//! declares bytes the file does not contain, must stay quiet. `ordinary_*` tests
//! elsewhere pin that side.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

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

/// A one-folder, uncompressed cabinet holding `payload`, whose directory lists
/// `files` as `(uoffFolderStart, size, NUL-terminated name)`.
#[cfg(feature = "cab")]
fn cab_with_files(payload: &[u8], files: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let files_off = 36 + 8;
    let data_off = files_off + files.iter().map(|f| 16 + f.2.len()).sum::<usize>();
    let mut blob = Vec::new();
    blob.extend_from_slice(b"MSCF");
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbCabinet (patched below)
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    blob.extend_from_slice(&(files_off as u32).to_le_bytes()); // coffFiles
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved3
    blob.extend_from_slice(&[3, 1]); // version
    blob.extend_from_slice(&1u16.to_le_bytes()); // cFolders
    blob.extend_from_slice(&(files.len() as u16).to_le_bytes()); // cFiles
    blob.extend_from_slice(&[0; 6]); // flags, setID, iCabinet
    blob.extend_from_slice(&(data_off as u32).to_le_bytes()); // coffCabStart
    blob.extend_from_slice(&1u16.to_le_bytes()); // cCFData
    blob.extend_from_slice(&0u16.to_le_bytes()); // typeCompress = none
    for (off, size, name) in files {
        blob.extend_from_slice(&size.to_le_bytes());
        blob.extend_from_slice(&off.to_le_bytes());
        blob.extend_from_slice(&[0; 8]); // iFolder, date, time, attribs
        blob.extend_from_slice(name);
    }
    blob.extend_from_slice(&0u32.to_le_bytes()); // csum
    blob.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // cbData
    blob.extend_from_slice(&(payload.len() as u16).to_le_bytes()); // cbUncomp
    blob.extend_from_slice(payload);
    let total = blob.len() as u32;
    blob[8..12].copy_from_slice(&total.to_le_bytes());
    assert_eq!(exav_unpack::detect(&blob), Some(Format::Cab));
    blob
}

/// Two CAB members may share their bytes: MSI cabinets list a file twice at one
/// offset when it is installed under two names, as ScreenConnect installers do.
/// A member that starts before the end of the previous one is read again from
/// the folder's start, not reported unreadable.
#[cfg(feature = "cab")]
#[test]
fn cab_members_that_share_bytes_are_all_read() {
    let files = [
        (0, 11, b"first\0".to_vec()),
        (0, 11, b"same_bytes\0".to_vec()),
        (6, 5, b"overlap\0".to_vec()),
    ];
    let blob = cab_with_files(b"hello world", &files);
    let mut budget = Budget::new(Limits::default());
    let mut got = Vec::new();
    let _ = extract_each::<()>(Format::Cab, &blob, &mut budget, &mut |e: Entry, _| {
        got.push((e.name, e.unsupported, e.data));
        None
    });
    let want: Vec<(String, Option<&str>, Vec<u8>)> = vec![
        ("first".into(), None, b"hello world".to_vec()),
        ("same_bytes".into(), None, b"hello world".to_vec()),
        ("overlap".into(), None, b"world".to_vec()),
    ];
    assert_eq!(got, want);
}

/// Each restart decodes the folder again up to the member, so a directory that
/// lists the same late member thousands of times is quadratic work unless it is
/// charged. It is, to the scan budget, and the walk stops as a limit.
#[cfg(feature = "cab")]
#[test]
fn cab_restarts_are_charged_to_the_scan_budget() {
    let payload = vec![b'x'; 1000];
    let files: Vec<_> = (0..200)
        .map(|i| (990, 10, format!("m{i}\0").into_bytes()))
        .collect();
    let blob = cab_with_files(&payload, &files);
    let mut limits = Limits::default();
    limits.max_scanned_bytes = 50_000;
    let mut budget = Budget::new(limits);
    let r = extract_each::<()>(Format::Cab, &blob, &mut budget, &mut |_, _| None);
    // Uncharged, the walk would read 200 × 10 bytes and succeed.
    let err = r.expect_err("200 restarts at offset 990 exceed a 50,000-byte budget");
    assert!(err.reason.contains("scan budget"), "{err:?}");
}
