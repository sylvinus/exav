//! cramfs: reading the filesystem, a block at a time.
//!
//! The images are what `mkcramfs` writes for the tree of `tree.py` and a file of
//! three blocks of zeros and a tail (`fixtures/fs/make.sh`): plain, padded by 512
//! bytes for boot code, with the empty blocks made holes, with extended block
//! pointers, and byte-swapped, as an image of a big-endian machine is.

use super::fs_tree::{assert_streams_alike, assert_tree, image, members, tree, walked};
use exav_unpack::{Format, Limits, detect};

const IMAGES: [&str; 5] = [
    "cramfs",
    "cramfs_padded",
    "cramfs_holes",
    "cramfs_extended",
    "cramfs_big_endian",
];

fn want() -> Vec<(String, Vec<u8>)> {
    let mut want = tree(false);
    let mut zeros = vec![0u8; 12288];
    zeros.extend_from_slice(b"end");
    want.push(("zeros.bin".to_string(), zeros));
    want
}

#[test]
fn a_cramfs_image_is_recognised() {
    for name in IMAGES {
        assert_eq!(detect(&image(name)), Some(Format::Cramfs), "{name}");
    }
}

#[test]
fn every_kind_of_image_reads_the_same_tree() {
    for name in IMAGES {
        let e = members(Format::Cramfs, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &want())).unwrap_or_else(|_| panic!("{name}"));
    }
}

#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in IMAGES {
        assert_streams_alike(Format::Cramfs, &image(name), 1000);
    }
}

#[test]
fn an_image_cut_short_is_reported() {
    let img = image("cramfs");
    let (e, end) = walked(Format::Cramfs, &img[..100], Limits::default());
    assert!(e.is_empty() && end.is_err());
    let (e, end) = walked(Format::Cramfs, &img[..img.len() / 2], Limits::default());
    assert!(end.is_err() || e.iter().any(|x| x.unsupported.is_some()));
}

/// A block that does not inflate is a file reported with what came before it.
#[test]
fn a_block_that_does_not_inflate_is_a_file_reported_with_what_precedes_it() {
    let mut img = image("cramfs");
    let at = img.len() - 3000;
    for b in &mut img[at..at + 1000] {
        *b ^= 0x5A;
    }
    let (e, _) = walked(Format::Cramfs, &img, Limits::default());
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "nothing was reported"
    );
    assert!(
        e.iter().any(|x| x.unsupported.is_none()),
        "nothing else was read"
    );
}
