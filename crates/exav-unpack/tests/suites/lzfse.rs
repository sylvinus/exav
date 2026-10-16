//! DMG runs compressed with LZFSE, through the whole extraction.
//!
//! `udif_lzfse.dmg` is `hfs_plus_udrw.dmg`'s disk in two LZFSE runs (an LZVN
//! block, then FSE blocks) written by an encoder that is not exav's
//! (`lzfse_rust`), so the files that come out are checked against the same
//! disk read from its raw runs.

use exav_unpack::{extract, Budget, Entry, Format, Limits};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/dmg/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn entries(data: &[u8]) -> Vec<Entry> {
    extract(Format::Dmg, &data, &mut Budget::new(Limits::default())).unwrap()
}

fn files(entries: &[Entry]) -> Vec<(String, Vec<u8>)> {
    entries
        .iter()
        .map(|e| (e.name.clone(), e.data.clone()))
        .collect()
}

#[test]
fn an_lzfse_image_gives_the_files_of_its_raw_twin() {
    let raw = entries(&fixture("hfs_plus_udrw.dmg"));
    let lzfse = entries(&fixture("udif_lzfse.dmg"));
    assert!(
        lzfse.iter().all(|e| e.unsupported.is_none()),
        "{:?}",
        lzfse
            .iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
    let want = files(&raw);
    assert!(want.iter().any(|(_, d)| d.starts_with(b"hello hfs+")));
    assert_eq!(files(&lzfse), want);
}

#[test]
fn an_lzfse_image_with_a_damaged_run_is_not_the_whole_image() {
    let image = fixture("udif_lzfse.dmg");
    // The second run is the one with the FSE block; its magic is damaged.
    let at = image.windows(4).rposition(|w| w == b"bvx2").unwrap();
    let mut bad = image.clone();
    bad[at + 3] = b'Z';
    let got = extract(
        Format::Dmg,
        &bad.as_slice(),
        &mut Budget::new(Limits::default()),
    );
    // Refused outright, or walked with the damage reported.
    if let Ok(got) = got {
        assert!(
            got.iter().any(|e| e.unsupported.is_some()),
            "a damaged run came out clean: {:?}",
            got.iter()
                .map(|e| (&e.name, e.unsupported))
                .collect::<Vec<_>>()
        );
    }
}
