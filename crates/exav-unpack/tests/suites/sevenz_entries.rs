//! 7z archives with entries that have no stream (directories and empty
//! files) among more than eight in all, so that the bit vectors of the
//! header span two bytes. `many_entries.7z` was written by p7zip 16.02:
//! `7z a -mx=1 -mtc=off -mta=off many_entries.7z top`, from a tree of three
//! directories, two empty files and ten files of 54 bytes.

use exav_unpack::{extract, Budget, Format, Limits};

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
