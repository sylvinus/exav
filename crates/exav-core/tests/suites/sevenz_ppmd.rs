//! A 7z member compressed with PPMd whose stream is cut short, at the verdict
//! level: the part never decoded leaves the file not clean.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

/// `ppmd_plain_header.7z` (see exav-unpack's `sevenz_ppmd` suite): one text
/// member, PPMd, the header uncompressed.
fn fixture() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/7z/ppmd_plain_header.7z"
    );
    std::fs::read(path).unwrap()
}

/// The packed size `archive` declares for its one packed stream, and where.
fn packed_size(archive: &[u8]) -> (u16, usize) {
    let header = 32 + u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
    // kHeader, kMainStreamsInfo, kPackInfo, pack position 0, one stream, kSize,
    // then the size as a two-byte 7z number.
    assert_eq!(
        archive[header..header + 6],
        [0x01, 0x04, 0x06, 0x00, 0x01, 0x09]
    );
    let at = header + 6;
    assert_eq!(archive[at] & 0xc0, 0x80);
    let size = (u16::from(archive[at] & 0x3f) << 8) | u16::from(archive[at + 1]);
    (size, at)
}

/// `archive` declaring `size` bytes for its packed stream.
fn with_packed_size(archive: &[u8], size: u16) -> Vec<u8> {
    assert!(size < 0x4000, "a two-byte 7z number");
    let (_, at) = packed_size(archive);
    let mut out = archive.to_vec();
    out[at] = 0x80 | (size >> 8) as u8;
    out[at + 1] = size as u8;
    out
}

/// `archive` declaring its packed stream half as long, so the PPMd decoder
/// runs out of input half way through the member.
fn packed_halved(archive: &[u8]) -> Vec<u8> {
    let (size, _) = packed_size(archive);
    with_packed_size(archive, size / 2)
}

/// `archive` with the pack sizes left out of its header, so its folder names
/// a packed stream the archive does not list.
fn without_pack_sizes(archive: &[u8]) -> Vec<u8> {
    let (_, at) = packed_size(archive);
    let mut out = [&archive[..at - 1], &archive[at + 2..]].concat();
    let header_size = u64::from_le_bytes(out[20..28].try_into().unwrap());
    out[20..28].copy_from_slice(&(header_size - 3).to_le_bytes());
    out
}

#[test]
fn a_7z_ppmd_member_cut_short_is_not_clean() {
    let db = Scanner::builtin();
    let archive = fixture();
    let verdict = |blob: &[u8]| analyze(&db, blob, &ScanOptions::default()).verdict;
    assert!(
        matches!(verdict(&archive), Verdict::Clean),
        "the whole archive holds nothing to find"
    );
    let cut = verdict(&packed_halved(&archive));
    assert!(
        !matches!(cut, Verdict::Clean),
        "half of the member was never decoded, got {cut:?}"
    );
}

/// A member whose packed bytes the header places past the end of the file, or
/// in a packed stream it does not list, was never decoded: not clean.
#[test]
fn a_7z_member_out_of_reach_is_not_clean() {
    let db = Scanner::builtin();
    let archive = fixture();
    let verdict = |blob: &[u8]| analyze(&db, blob, &ScanOptions::default()).verdict;
    assert!(32 + 0x3fff > archive.len());
    for (what, blob) in [
        ("past the end", with_packed_size(&archive, 0x3fff)),
        ("no packed stream", without_pack_sizes(&archive)),
    ] {
        let v = verdict(&blob);
        assert!(!matches!(v, Verdict::Clean), "{what}: got {v:?}");
    }
}
