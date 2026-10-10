//! 7z members compressed with PPMd (variant H), whole and cut short, and a
//! member whose packed bytes the header places out of reach.
//!
//! `ppmd_plain_header.7z` was written by 7-Zip 25.01:
//! `7z a -t7z -m0=PPMd -mhc=off ppmd_plain_header.7z known.txt` (order 6,
//! 16 MB), its header left uncompressed so a test can rewrite the packed size
//! declared in it.

use exav_unpack::{extract, Budget, Format, Limits};

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/7z/ppmd_plain_header.7z",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// `known.txt`, the archive's one member.
fn known() -> Vec<u8> {
    let mut t = b"exav data descriptor fixture\n".to_vec();
    for i in 1..=40 {
        t.extend_from_slice(
            format!("line {i:02}: the quick brown fox jumps over the lazy dog\n").as_bytes(),
        );
    }
    t
}

/// The packed size `archive` declares for its one packed stream, and where.
fn packed_size(archive: &[u8]) -> (u16, usize) {
    let header = 32 + u64::from_le_bytes(archive[12..20].try_into().unwrap()) as usize;
    // kHeader, kMainStreamsInfo, kPackInfo, pack position 0, one stream, kSize.
    assert_eq!(
        archive[header..header + 6],
        [0x01, 0x04, 0x06, 0x00, 0x01, 0x09]
    );
    // A two-byte 7z number: `10` and the high 6 bits, then the low byte.
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

/// `archive` declaring a packed stream `by` bytes shorter: the PPMd stream is
/// cut short, and everything else is intact.
fn packed_shorter(archive: &[u8], by: u16) -> Vec<u8> {
    let (size, _) = packed_size(archive);
    with_packed_size(archive, size - by)
}

/// `archive` with the pack sizes left out of its header (`kSize` is optional
/// in the pack info), so its one folder names a packed stream the archive does
/// not list.
fn without_pack_sizes(archive: &[u8]) -> Vec<u8> {
    let (_, at) = packed_size(archive);
    // kSize and the two-byte size.
    let mut out = [&archive[..at - 1], &archive[at + 2..]].concat();
    let header_size = u64::from_le_bytes(out[20..28].try_into().unwrap());
    out[20..28].copy_from_slice(&(header_size - 3).to_le_bytes());
    out
}

fn members(blob: &[u8]) -> Vec<(String, Option<&'static str>, Vec<u8>)> {
    extract(Format::SevenZip, &blob, &mut Budget::new(Limits::default()))
        .unwrap()
        .into_iter()
        .map(|e| (e.name, e.unsupported, e.data))
        .collect()
}

#[test]
fn a_ppmd_member_written_by_7zip_is_decoded() {
    let got = members(&fixture());
    assert!(
        got == [("known.txt".to_string(), None, known())],
        "{:?}",
        got.iter()
            .map(|g| (&g.0, g.1, g.2.len()))
            .collect::<Vec<_>>()
    );
}

/// The decoder runs out of input before the member's declared size. What it
/// decoded is handed over and scanned, and the member says it is not whole:
/// the stream ending early was taken for the member's end.
#[test]
fn a_ppmd_stream_cut_short_is_not_a_whole_member() {
    let archive = fixture();
    let (size, _) = packed_size(&archive);
    let known = known();
    for by in [size / 4, size / 2, size - 8] {
        let got = members(&packed_shorter(&archive, by));
        let summary: Vec<_> = got.iter().map(|g| (&g.0, g.1, g.2.len())).collect();
        assert_eq!(got.len(), 1, "cut by {by}: {summary:?}");
        let (name, unsupported, data) = &got[0];
        assert_eq!(name, "known.txt");
        assert!(unsupported.is_some(), "cut by {by}: {summary:?}");
        assert!(
            data.len() < known.len() && known.starts_with(data),
            "cut by {by}: not a prefix of the member: {summary:?}"
        );
    }
}

/// The header places the member's packed bytes partly past the end of the
/// file. The directory names the member and its bytes start in the file, so
/// it is reported rather than left out of the listing.
#[test]
fn a_packed_stream_past_the_end_of_the_file_is_reported() {
    let archive = fixture();
    assert!(32 + 0x3fff > archive.len());
    let got = members(&with_packed_size(&archive, 0x3fff));
    let summary: Vec<_> = got.iter().map(|g| (&g.0, g.1, g.2.len())).collect();
    assert_eq!(got.len(), 1, "{summary:?}");
    assert_eq!(got[0].0, "known.txt");
    assert!(got[0].1.is_some(), "{summary:?}");
}

/// A folder naming a packed stream the header does not list: the member has
/// no bytes exav can locate, and is reported.
#[test]
fn a_folder_without_its_packed_stream_is_reported() {
    let got = members(&without_pack_sizes(&fixture()));
    let summary: Vec<_> = got.iter().map(|g| (&g.0, g.1, g.2.len())).collect();
    assert_eq!(got.len(), 1, "{summary:?}");
    assert_eq!(got[0].0, "known.txt");
    assert!(got[0].1.is_some(), "{summary:?}");
}
