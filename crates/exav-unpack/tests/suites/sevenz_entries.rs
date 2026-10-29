//! 7z archives with entries that have no stream (directories and empty
//! files) among more than eight in all, so that the bit vectors of the
//! header span two bytes. `many_entries.7z` was written by p7zip 16.02:
//! `7z a -mx=1 -mtc=off -mta=off many_entries.7z top`, from a tree of three
//! directories, two empty files and ten files of 54 bytes.

use exav_unpack::{Budget, Format, Limits, extract};

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/7z/many_entries.7z",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
fn the_empty_entries_of_a_larger_archive_do_not_misplace_the_names_after_them() {
    let entries = extract(
        Format::SevenZip,
        &fixture(),
        &mut Budget::new(Limits::default()),
    )
    .unwrap();
    for i in 0..10 {
        let want = format!("content of file {i}\n").repeat(3);
        let name = format!("top/file{i}.txt");
        let e = entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
            panic!(
                "{name} among {:?}",
                entries.iter().map(|e| &e.name).collect::<Vec<_>>()
            )
        });
        assert_eq!(e.data, want.as_bytes(), "{name}");
    }
    // A directory is not a file.
    for dir in ["top", "top/empty_dir", "top/sub"] {
        assert!(!entries.iter().any(|e| e.name == dir), "{dir}");
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// An archive of nothing but a header: `files` entries and `props` properties
/// of them that mean nothing.
fn header_only(files: u32, props: usize) -> Vec<u8> {
    let mut header = vec![0x01, 0x05];
    // A 7z number of three bytes.
    header.extend([0xC0 | (files >> 16) as u8, files as u8, (files >> 8) as u8]);
    for _ in 0..props {
        header.extend([0x30, 0x00]);
    }
    header.extend([0x00, 0x00]);
    let mut start = Vec::new();
    start.extend(0u64.to_le_bytes());
    start.extend((header.len() as u64).to_le_bytes());
    start.extend(crc32(&header).to_le_bytes());
    let mut out = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    out.extend(crc32(&start).to_le_bytes());
    out.extend(start);
    out.extend(header);
    out
}

/// The entries without a stream are counted when the property that sets them
/// is read, not again for every property that follows.
#[test]
fn a_header_of_many_properties_over_many_files_is_read_in_linear_time() {
    let blob = header_only(100_000, 100_000);
    let start = std::time::Instant::now();
    let _ = extract(Format::SevenZip, &blob, &mut Budget::new(Limits::default()));
    assert!(start.elapsed().as_secs() < 3, "{:?}", start.elapsed());
}
