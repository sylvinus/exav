//! EROFS: reading the filesystem, which stores its files where an inode says.
//!
//! The images are what `mkfs.erofs` writes for the tree of `tree.py` and a link
//! (`fixtures/fs/make.sh`): with blocks of 4 KiB and of 1 KiB, with the small
//! inodes, in chunks (and the sparse file's holes), and compressed: with LZ4,
//! and, with the files of `zextras.py` added, with each algorithm, the full
//! index, physical clusters of 64 KiB, the last extent after the index, and
//! the tails in the packed inode, which are reported.

use super::fs_tree::{assert_streams_alike, assert_tree, came, image, members, pat, tree, walked};
use exav_unpack::{Format, Limits, Member, detect};

/// Bytes a compressor cannot shrink (`noise` of `zextras.py`).
fn noise(seed: u64, n: usize) -> Vec<u8> {
    (0..n as u64)
        .map(|i| {
            ((i.wrapping_mul(2654435761).wrapping_add(seed * 40503) & 0xFFFF_FFFF) >> 13) as u8
        })
        .collect()
}

/// `n` bytes of a block of 4099, repeated (`rep` of `zextras.py`).
fn rep(seed: u32, n: usize) -> Vec<u8> {
    pat(seed, 4099).into_iter().cycle().take(n).collect()
}

/// The files `zextras.py` adds to the tree.
fn z_extras() -> Vec<(String, Vec<u8>)> {
    let mut mixed = Vec::new();
    let mut k = 0u32;
    while mixed.len() < 120000 {
        match k % 2 {
            0 => mixed.extend(noise(60 + u64::from(k), 20000)),
            _ => mixed.extend(rep(70 + k, 20000)),
        }
        k += 1;
    }
    mixed.truncate(120000);
    vec![
        ("z/rep.bin".to_string(), rep(7, 1500000)),
        ("z/zeros.bin".to_string(), vec![0; 3000000]),
        ("z/noise.bin".to_string(), noise(5, 20000)),
        ("z/mixed.bin".to_string(), mixed),
    ]
}

/// The images with `zextras.py`'s files, by what they were made with.
const Z_IMAGES: [&str; 10] = [
    "lz4", "lz4hc", "lzma", "deflate", "zstd", "legacy", "big", "lzma_big", "tail", "blocks1k",
];

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

/// The tree comes out whole from a compressed image, whatever the algorithm and
/// the layout of the index.
#[test]
fn the_tree_comes_out_of_every_compressed_image() {
    let e = members(Format::Erofs, &image("erofs_lz4"));
    assert_tree(&e, &tree(false));
    let mut want = tree(false);
    want.extend(z_extras());
    for name in Z_IMAGES {
        let e = members(Format::Erofs, &image(&format!("erofs_z_{name}")));
        std::panic::catch_unwind(|| assert_tree(&e, &want))
            .unwrap_or_else(|_| panic!("erofs_z_{name}"));
    }
}

/// A file past the buffer limit is read as it goes, extent by extent, and is
/// the same bytes as held. The limit holds what one extent needs: a physical
/// cluster (64 KiB at most in these images) and, for LZMA, a dictionary as
/// long as the extent reaches back (`frag.bin` is one extent of 100,000 bytes).
#[test]
fn compressed_files_over_the_buffer_limit_are_read_as_they_go() {
    for name in Z_IMAGES {
        assert_streams_alike(Format::Erofs, &image(&format!("erofs_z_{name}")), 1 << 17);
    }
}

/// A buffer limit below a physical cluster cannot hold one: the files that
/// need it fail or are reported, none comes out short with nothing said.
#[test]
fn a_cluster_over_the_buffer_limit_is_reported_not_cut() {
    for name in ["lz4", "lzma", "deflate", "zstd", "big"] {
        let img = image(&format!("erofs_z_{name}"));
        let held = members(Format::Erofs, &img);
        let (got, end) = came(Format::Erofs, &img, 1000);
        end.unwrap();
        assert_eq!(got.len(), held.len(), "{name}");
        let mut failed = 0;
        for (c, h) in got.iter().zip(&held) {
            if c.data != h.data {
                let why = c
                    .read_error
                    .clone()
                    .or_else(|| c.unsupported.map(String::from))
                    .unwrap_or_else(|| panic!("{name}: {}", c.name));
                // The reason is the limit's, not a generic one.
                assert!(why.contains("over the buffer limit"), "{name}: {why}");
                failed += 1;
            }
        }
        assert!(
            failed > 0,
            "{name}: no file needed a cluster over the limit"
        );
    }
}

/// The dictionary of an LZMA extent is bounded by the buffer limit. An extent
/// that reaches back further fails where it does: the bytes before are given,
/// then the read ends with an error.
#[test]
fn an_lzma_extent_reaching_back_past_the_buffer_limit_fails_where_it_does() {
    let img = image("erofs_z_lzma_big");
    let held = members(Format::Erofs, &img);
    let (got, end) = came(Format::Erofs, &img, 1 << 16);
    end.unwrap();
    let c = got.iter().find(|c| c.name == "frag.bin").unwrap();
    let h = held.iter().find(|h| h.name == "frag.bin").unwrap();
    assert!(c.read_error.is_some(), "the read went on: {}", c.data.len());
    assert!(!c.data.is_empty() && c.data.len() < h.data.len());
    assert!(h.data.starts_with(&c.data));
}

/// A file whose tail is in the packed inode is reported, and the others come out.
#[test]
fn a_file_with_its_tail_in_the_packed_inode_is_reported() {
    let e = members(Format::Erofs, &image("erofs_z_fragments"));
    let mut want = tree(false);
    want.extend(z_extras());
    let mut reported = 0;
    for (path, data) in &want {
        let m = e.iter().find(|x| &x.name == path).unwrap();
        match m.unsupported {
            None => assert!(&m.data == data, "{path}"),
            Some(why) => {
                assert!(why.contains("packed inode"), "{path}: {why}");
                reported += 1;
            }
        }
    }
    assert!(reported > 0);
}

/// 64 MiB of zeros, in extents of up to 8 MiB, is read through a window, as a
/// member that is not held, with each algorithm.
#[test]
fn a_long_compressed_file_is_never_held() {
    for name in ["lz4hc", "lzma", "deflate", "zstd"] {
        let img = image(&format!("erofs_zeros_{name}"));
        let mut limits = Limits::default();
        limits.max_buffer_bytes = 1 << 20;
        let mut budget = exav_unpack::Budget::new(limits);
        let mut seen = (0u64, false);
        exav_unpack::walk(Format::Erofs, &img, &mut budget, &mut |meta, content, _| {
            match content {
                Some(Member::Stream(r)) => {
                    let mut buf = vec![0u8; 1 << 16];
                    let mut total = 0u64;
                    while let Ok(n) = std::io::Read::read(r, &mut buf) {
                        if n == 0 {
                            break;
                        }
                        assert!(buf[..n].iter().all(|&b| b == 0), "{name}: {}", meta.name);
                        total += n as u64;
                    }
                    seen = (total, true);
                }
                _ => panic!("{name}: held {}", meta.name),
            }
            None::<()>
        })
        .unwrap();
        assert_eq!(seen, (64 << 20, true), "{name}");
    }
}

#[test]
fn an_image_cut_short_is_reported() {
    let img = image("erofs");
    let (e, end) = walked(Format::Erofs, &img[..1100], Limits::default());
    assert!(e.is_empty() && end.is_err());
    let (e, end) = walked(Format::Erofs, &img[..img.len() / 2], Limits::default());
    assert!(end.is_err() || e.iter().any(|x| x.unsupported.is_some()));
}

/// A compressed file that breaks part way says why, held or read as it goes,
/// and gives the bytes decoded before the break. `erofs_z_lz4` has one byte
/// changed, where its index or the coded bytes of one file are (the offsets
/// were found by changing each byte in turn).
#[test]
fn a_compressed_file_that_breaks_part_way_says_why() {
    let img = image("erofs_z_lz4");
    let intact = members(Format::Erofs, &img);
    let flipped = |at: usize| {
        let mut d = img.clone();
        d[at] ^= 0xFF;
        d
    };
    // The image, the file, the reason, and whether the file comes short. (The
    // byte of the fourth is in the size of the inode: the file is all there,
    // and then is said to go on.)
    let cases = [
        (
            flipped(2420),
            "frag.bin",
            "did not decode to their extent",
            true,
        ),
        (
            flipped(2398),
            "frag.bin",
            "coded bytes could not be opened",
            true,
        ),
        (flipped(2376), "frag.bin", "map of extents", true),
        (
            flipped(4015),
            "a/b/c/deep.bin",
            "stored extent longer than its blocks",
            false,
        ),
    ];
    // The reason a member came with: reported, or the error of its read.
    let reason = |c: &super::fs_tree::Came| {
        c.unsupported
            .map(String::from)
            .or_else(|| c.read_error.clone())
    };
    for (damaged, name, why, short) in cases {
        let h = intact.iter().find(|m| m.name == name).unwrap();
        for cap in [1 << 30, h.data.len() as u64 - 1] {
            let (got, _) = came(Format::Erofs, &damaged, cap);
            let c = got.iter().find(|c| c.name == name).expect(name);
            let said = reason(c);
            assert!(
                said.as_ref().is_some_and(|s| s.contains(why)),
                "{name}, buffer limit {cap}: {said:?}"
            );
            assert!(
                c.data.len() < h.data.len() || !short,
                "{name}, buffer limit {cap}"
            );
        }
    }
}
