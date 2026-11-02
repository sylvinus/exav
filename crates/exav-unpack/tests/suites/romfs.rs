//! romfs: reading the filesystem, which stores its files as they are.
//!
//! The images are what `genromfs` writes for the tree of `tree.py`, with a hard
//! link to a file, a link that holds no file, and (the second) every file
//! aligned to 512 bytes (`fixtures/fs/make.sh`).

use super::fs_tree::{assert_streams_alike, assert_tree, image, members, pat, tree, walked};
use exav_unpack::{Format, Limits, detect};

fn want() -> Vec<(String, Vec<u8>)> {
    let mut want = tree(false);
    // The hard link is the file it names.
    want.push(("hard".to_string(), pat(1, 10)));
    want
}

#[test]
fn a_romfs_image_is_recognised() {
    assert_eq!(detect(&image("romfs")), Some(Format::Romfs));
}

#[test]
fn the_tree_comes_out_with_its_hard_link() {
    for name in ["romfs", "romfs_aligned"] {
        let e = members(Format::Romfs, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &want())).unwrap_or_else(|_| panic!("{name}"));
    }
}

#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in ["romfs", "romfs_aligned"] {
        assert_streams_alike(Format::Romfs, &image(name), 1000);
    }
}

/// The files carry the mode a romfs header can say: executable or not.
#[test]
fn a_file_comes_with_whether_it_is_executable() {
    let e = members(Format::Romfs, &image("romfs"));
    let mode = |n: &str| e.iter().find(|x| x.name == n).unwrap().mode;
    assert_eq!(mode("tiny.txt"), Some(0o100755));
    assert_eq!(mode("empty"), Some(0o100644));
}

#[test]
fn an_image_cut_short_is_reported() {
    let img = image("romfs");
    let (e, end) = walked(Format::Romfs, &img[..40], Limits::default());
    assert!(e.is_empty() && end.is_err());
    let (e, end) = walked(Format::Romfs, &img[..img.len() / 2], Limits::default());
    assert!(end.is_err() || e.iter().any(|x| x.unsupported.is_some()));
}
