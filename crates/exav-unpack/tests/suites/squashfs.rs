//! SquashFS: reading the filesystem, a block at a time.
//!
//! The images are what `mksquashfs` writes for the tree of `tree.py`, in each
//! of its compressions, with blocks of 4 KiB, and with nothing compressed
//! (`fixtures/fs/make.sh`). The tree has a file of 70 MiB that is holes but for
//! three places in it, and a link, which holds no file.

use super::fs_tree::{assert_streams_alike, assert_tree, image, members, tree, walked};
use exav_unpack::{Format, Limits, detect};

const IMAGES: [&str; 8] = [
    "squashfs_gzip",
    "squashfs_xz",
    "squashfs_lzo",
    "squashfs_lz4",
    "squashfs_zstd",
    "squashfs_lzma",
    "squashfs_small_blocks",
    "squashfs_uncompressed",
];

#[test]
fn a_squashfs_image_is_recognised() {
    for name in IMAGES {
        assert_eq!(detect(&image(name)), Some(Format::Squashfs), "{name}");
    }
}

/// The same tree comes out of an image in every compression, in blocks of 128
/// KiB and of 4 KiB, with tails in fragments and without compression, with the
/// holes of the sparse file read as zeros.
#[test]
fn every_compression_reads_the_same_tree() {
    for name in IMAGES {
        let e = members(Format::Squashfs, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &tree(true)))
            .unwrap_or_else(|_| panic!("{name}"));
    }
}

/// A file over the buffer limit is read as it goes, whatever compresses its
/// blocks.
#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in IMAGES {
        assert_streams_alike(Format::Squashfs, &image(name), 1000);
    }
}

/// An image cut short is a filesystem whose tables are not all there; the files
/// before the cut are partial or reported.
#[test]
fn an_image_cut_short_is_reported() {
    let img = image("squashfs_gzip");
    let (e, end) = walked(Format::Squashfs, &img[..200], Limits::default());
    assert!(e.is_empty() && end.is_err());
    let (e, end) = walked(Format::Squashfs, &img[..img.len() / 2], Limits::default());
    assert!(end.is_err() || e.iter().any(|x| x.unsupported.is_some()));
}

/// A block that does not decompress is a file reported with what came before.
#[test]
fn a_block_that_does_not_decompress_is_a_file_reported_with_what_precedes_it() {
    let mut img = image("squashfs_small_blocks");
    // The data blocks begin after the 96 bytes of the superblock; spoil the
    // middle of the data, which is a few blocks of a few files.
    for b in &mut img[2000..3000] {
        *b ^= 0xA5;
    }
    let (e, end) = walked(Format::Squashfs, &img, Limits::default());
    let _ = end;
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "nothing was reported"
    );
    assert!(
        e.iter().any(|x| x.unsupported.is_none()),
        "nothing else was read"
    );
}
