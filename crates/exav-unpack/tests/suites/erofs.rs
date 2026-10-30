//! EROFS: reading the filesystem, which stores its files where an inode says.
//!
//! The images are what `mkfs.erofs` writes for the tree of `tree.py` and a link
//! (`fixtures/fs/make.sh`): with blocks of 4 KiB and of 1 KiB, with the small
//! inodes, in chunks (and the sparse file's holes), and compressed with LZ4,
//! which is reported and not read.

use super::fs_tree::{assert_streams_alike, assert_tree, image, members, tree, walked};
use exav_unpack::{Format, Limits, detect};

#[test]
fn an_erofs_image_is_recognised() {
    for name in ["erofs", "erofs_chunks", "erofs_lz4"] {
        assert_eq!(detect(&image(name)), Some(Format::Erofs), "{name}");
    }
}

/// The tree comes out whole: files whose tail is kept after their inode, files
/// in whole blocks, and files in chunks with holes.
#[test]
fn the_tree_comes_out_of_every_uncompressed_layout() {
    for (name, sparse) in [
        ("erofs", false),
        ("erofs_small_blocks", false),
        ("erofs_compact_inodes", false),
        ("erofs_chunks", true),
    ] {
        let e = members(Format::Erofs, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &tree(sparse)))
            .unwrap_or_else(|_| panic!("{name}"));
    }
}

/// A file over the buffer limit is read as it goes in every layout: whole
/// blocks, a tail after the inode, and chunks with holes.
#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in [
        "erofs",
        "erofs_small_blocks",
        "erofs_compact_inodes",
        "erofs_chunks",
    ] {
        assert_streams_alike(Format::Erofs, &image(name), 1000);
    }
}

/// A file stored compressed is reported, not read as though it were plain, and
/// the files that were stored as they are come out.
#[test]
fn a_compressed_file_is_reported_and_the_directories_are_still_read() {
    let e = members(Format::Erofs, &image("erofs_lz4"));
    let want = tree(false);
    assert_eq!(e.len(), want.len(), "every file is a member");
    for (path, data) in &want {
        let m = e.iter().find(|x| &x.name == path).unwrap();
        match m.unsupported {
            None => assert_eq!(&m.data, data, "{path}"),
            Some(why) => assert_eq!(why, "EROFS compressed file not read", "{path}"),
        }
    }
    assert!(e.iter().any(|x| x.unsupported.is_some()));
}

#[test]
fn an_image_cut_short_is_reported() {
    let img = image("erofs");
    let (e, end) = walked(Format::Erofs, &img[..1100], Limits::default());
    assert!(e.is_empty() && end.is_err());
    let (e, end) = walked(Format::Erofs, &img[..img.len() / 2], Limits::default());
    assert!(end.is_err() || e.iter().any(|x| x.unsupported.is_some()));
}
