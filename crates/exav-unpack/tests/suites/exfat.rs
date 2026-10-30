//! exFAT: reading the filesystem, not carving the clusters.
//!
//! The images are written by a kernel (`fixtures/fs/make.sh`): the tree of
//! `tree.py`, written across the holes of deleted files so that the larger ones
//! are chained and not in a row, and a file given a length longer than what was
//! written to it. Clusters of 4 KiB and of 512 bytes.

use super::fs_tree::{assert_streams_alike, assert_tree, image, members, tree, truncated, walked};
use exav_unpack::{Format, Limits, detect};

fn want() -> Vec<(String, Vec<u8>)> {
    let mut want = tree(false);
    want.push(truncated());
    want
}

#[test]
fn an_exfat_volume_is_recognised() {
    assert_eq!(detect(&image("exfat")), Some(Format::Exfat));
}

/// The tree comes out whole, the files that are chained as well as those in a
/// row, and the file that was lengthened reads as zeros past what was written,
/// though the clusters it was given held other files' bytes before.
#[test]
fn the_tree_comes_out_of_a_volume_a_kernel_wrote() {
    for name in ["exfat", "exfat_small_clusters"] {
        let e = members(Format::Exfat, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &want())).unwrap_or_else(|_| panic!("{name}"));
    }
}

/// A file over the buffer limit is read as it goes: the chained ones, those in
/// a row, and the one lengthened past what was written.
#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in ["exfat", "exfat_small_clusters"] {
        assert_streams_alike(Format::Exfat, &image(name), 1000);
    }
}

#[test]
fn an_image_cut_short_is_reported() {
    let img = image("exfat");
    let (_, end) = walked(Format::Exfat, &img[..2048], Limits::default());
    assert!(end.unwrap_err().is_corrupt());
    // Cut where the files are, the volume opens and the files are partial.
    let heap = u32::from_le_bytes(img[88..92].try_into().unwrap()) as usize * 512;
    let (e, _) = walked(Format::Exfat, &img[..heap + 200 * 1024], Limits::default());
    assert!(e.iter().any(|x| x.unsupported.is_some()));
}

/// The place of the file entry of the set named `name`.
fn set_of(img: &[u8], name: &str) -> usize {
    let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    (0..img.len().saturating_sub(96))
        .step_by(32)
        .find(|&p| {
            img[p] == 0x85
                && img[p + 32] == 0xC0
                && img[p + 64] == 0xC1
                && usize::from(img[p + 35]) == name.len()
                && img[p + 66..].starts_with(&units)
        })
        .unwrap_or_else(|| panic!("no entry {name}"))
}

/// A folder that names the folder it is in is walked once.
#[test]
fn a_folder_that_names_the_folder_it_is_in_is_walked_once() {
    let mut img = image("exfat");
    let a = set_of(&img, "a");
    let b = set_of(&img, "b");
    let first: [u8; 4] = img[a + 32 + 20..a + 32 + 24].try_into().unwrap();
    img[b + 32 + 20..b + 32 + 24].copy_from_slice(&first);
    let e = members(Format::Exfat, &img);
    let mut want = want();
    want.retain(|(p, _)| p != "a/b/c/deep.bin");
    assert_tree(&e, &want);
}

/// A file that is no longer said to be in a row is followed in the table, which
/// holds no chain for it: it is reported with its first cluster.
#[test]
fn a_chain_the_table_does_not_hold_is_a_file_reported_with_what_it_has() {
    let mut img = image("exfat");
    let at = set_of(&img, "frag.bin") + 32;
    assert_eq!(img[at + 1] & 2, 2, "the fixture's file is in a row");
    img[at + 1] &= !2;
    let (e, end) = walked(Format::Exfat, &img, Limits::default());
    end.unwrap();
    let f = e.iter().find(|x| x.name == "frag.bin").unwrap();
    assert_eq!(
        f.unsupported,
        Some("file could not be read from the volume")
    );
    assert_eq!(f.data.len(), 4096);
}
