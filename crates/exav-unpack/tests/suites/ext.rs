//! ext2/3/4 — reading the filesystem, not carving the blocks.
//!
//! Same argument as the FAT suite next door. A raw disk is a pile of blocks;
//! carving finds a file whose magic sits at the start of a contiguous run and
//! misses everything else. A **fragmented** file — one written into a hole left
//! by a deleted file and continuing past it — comes back as disconnected pieces
//! that will not decompress.
//!
//! The fixture is built to be exactly that case. Three 64 KB files written, the
//! middle one deleted, then a ~96 KB payload written so it lands in the 64 KB
//! hole and continues after `c.bin`. `debugfs` confirms the inode:
//!
//! ```text
//! EXTENTS: (0-62):371-433, (63-96):498-531
//! ```
//!
//! Two extents, non-adjacent. The payload is a ZIP whose EICAR member is
//! deflated, so the signature bytes appear nowhere in the image — only walking
//! the extent tree reassembles it.
//!
//! Regenerate with (`e2fsprogs`):
//! ```sh
//! dd if=/dev/zero of=frag.img bs=1M count=4
//! mke2fs -q -t ext4 -b 1024 -O ^has_journal frag.img
//! debugfs -w -f - frag.img <<'EOD'
//! write padA a.bin
//! write padB b.bin
//! write padC c.bin
//! rm b.bin
//! mkdir /sub
//! cd /sub
//! write payload.zip p.zip
//! quit
//! EOD
//! gzip -9 frag.img
//! ```

use super::extract_each;
use super::fs_tree::{
    assert_streams_alike, assert_tree, came, extras, image, members as walk_members, pat, tree,
    walked,
};
use exav_unpack::{Budget, Entry, Format, Limits, detect};

/// `sha256sum` of the ZIP that was written in, which is what following the
/// extent tree has to reproduce.
const PAYLOAD: &str = "d61da8b0c3cd1d5ffa812601aae787c81a7424850c4dca15c27e593f8f92fcc8";

pub(super) fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/ext/fragmented.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = exav_unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut out = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(std::io::Cursor::new(raw)),
        &mut out,
    )
    .unwrap_or_else(|e| panic!("gunzip {p}: {e}"));
    out
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn members(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Ext,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

#[test]
fn an_ext_image_is_recognised() {
    assert_eq!(detect(&fixture()), Some(Format::Ext));
}

#[test]
fn a_fragmented_file_is_reassembled_from_its_extent_tree() {
    let e = members(&fixture());
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy image must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let p = e
        .iter()
        .find(|x| x.name.ends_with("p.zip"))
        .unwrap_or_else(|| {
            panic!(
                "the payload must be found, with its path; got {:?}",
                e.iter().map(|x| &x.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        sha256_hex(&p.data),
        PAYLOAD,
        "the file spans two non-adjacent extents, so anything short of walking \
         the tree returns fragments rather than the file"
    );
}

#[test]
fn files_come_back_with_their_directory_paths() {
    let e = members(&fixture());
    let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("sub/")),
        "a file in a subdirectory should carry its path, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n.ends_with("a.bin")),
        "top-level files must be walked too, got {names:?}"
    );
}

#[test]
fn the_payload_is_absent_from_the_raw_image() {
    // Guards the premise: if EICAR were visible in the blocks, a raw scan would
    // find it without reading the filesystem and this fixture would prove
    // nothing about the extent walk.
    let eicar = exav_unpack::eicar();
    let img = fixture();
    assert!(!img.windows(eicar.len()).any(|w| w == eicar));
}

#[test]
fn the_filesystems_own_bookkeeping_is_not_emitted_as_a_file() {
    // `lost+found` is a directory the filesystem makes for itself, and the
    // block/inode bitmaps are not files at all. Emitting them would bury the
    // real content in noise on every image.
    let e = members(&fixture());
    assert!(
        !e.iter().any(|x| x.name.contains("lost+found/")),
        "lost+found is empty on a fresh image; nothing should come out of it: {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
}

#[test]
fn a_corrupt_filesystem_is_reported_not_shrugged_off() {
    // The superblock still says ext, so the files are there and a real mount
    // would read them; failing to must not read as clean.
    let mut img = fixture();
    // Scribble over the block group descriptors, which sit right after the
    // superblock and are how every inode is located.
    for b in &mut img[2048..8192] {
        *b = 0xFF;
    }
    let (e, end) = walked(Format::Ext, &img, Limits::default());
    assert!(e.is_empty());
    assert!(end.unwrap_err().is_corrupt());
}

/// A file over the buffer limit is read as it goes, and comes out as it does
/// held, in every layout of the filesystem.
#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in [
        "ext4",
        "ext2_blockmap",
        "ext3",
        "ext4_metabg",
        "ext4_bigalloc",
    ] {
        assert_streams_alike(Format::Ext, &image(name), 8192);
    }
    let (e, end) = came(Format::Ext, &image("ext4"), 8192);
    end.unwrap();
    let by = |n: &str| e.iter().find(|x| x.name == n).unwrap();
    assert!(by("frag.bin").streamed);
    assert_eq!(by("frag.bin").data.len(), 100000);
    assert!(!by("big4k.bin").streamed);
    assert!(!by("many/file_299.dat").streamed);
}

/// The same tree comes out of every layout of the filesystem: extents, block
/// maps with their three levels of indirection, data in the inode, descriptors
/// in meta block groups, and clusters of several blocks.
#[test]
fn every_layout_of_the_filesystem_reads_the_same_tree() {
    for name in [
        "ext4",
        "ext2_blockmap",
        "ext3",
        "ext4_inline",
        "ext4_metabg",
        "ext4_bigalloc",
    ] {
        let e = walk_members(Format::Ext, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &tree(true)))
            .unwrap_or_else(|_| panic!("{name}"));
    }
}

/// A volume a kernel wrote: preallocated space reads as zeros, a punched hole
/// reads as zeros, and a file written across the holes of deleted ones comes
/// back whole.
#[test]
fn a_volume_a_kernel_wrote_reads_as_the_kernel_shows_it() {
    let mut want = tree(false);
    want.extend(extras());
    let e = walk_members(Format::Ext, &image("ext4_kernel"));
    assert_tree(&e, &want);
}

/// The place of inode `ino` in `img`, an ext4 volume of 4 KiB blocks.
fn inode_at(img: &[u8], ino: usize) -> usize {
    let le32 = |at: usize| u32::from_le_bytes(img[at..at + 4].try_into().unwrap()) as usize;
    let (ipg, size) = (
        le32(1024 + 40),
        u16::from_le_bytes([img[1024 + 88], img[1024 + 89]]),
    );
    let (group, slot) = ((ino - 1) / ipg, (ino - 1) % ipg);
    // The descriptors start in block 1 and are 64 bytes each with 64bit.
    let desc = 4096 + group * 64;
    le32(desc + 8) * 4096 + slot * usize::from(size)
}

/// The inode number a name has in a directory block of `img`.
fn ino_of(img: &[u8], name: &str) -> (usize, usize) {
    // An entry: inode, length, name length, type, name.
    let entry = |p: usize| {
        p >= 8 && {
            let rec = usize::from(u16::from_le_bytes([img[p - 4], img[p - 3]]));
            img[p - 2] == name.len() as u8
                && (1..=7).contains(&img[p - 1])
                && rec % 4 == 0
                && rec >= 8 + name.len()
        }
    };
    let at = img
        .windows(name.len())
        .enumerate()
        .position(|(p, w)| w == name.as_bytes() && entry(p))
        .unwrap_or_else(|| panic!("no entry {name}"));
    let ino = u32::from_le_bytes(img[at - 8..at - 4].try_into().unwrap()) as usize;
    (ino, at - 8)
}

/// A directory that names one above it is walked once, not forever.
#[test]
fn a_directory_that_names_its_ancestor_is_walked_once() {
    let mut img = image("ext4");
    let (_, at) = ino_of(&img, "emptydir");
    img[at..at + 4].copy_from_slice(&2u32.to_le_bytes());
    let e = walk_members(Format::Ext, &img);
    assert_tree(&e, &tree(true));
}

/// A file whose extent tree is gone is reported, and the others come out.
#[test]
fn a_file_with_a_damaged_extent_tree_is_reported_and_the_others_are_read() {
    let mut img = image("ext4");
    let (ino, _) = ino_of(&img, "big4k.bin");
    // The extent header's magic, 40 bytes into the inode.
    let at = inode_at(&img, ino) + 40;
    assert_eq!(&img[at..at + 2], &[0x0A, 0xF3]);
    img[at] = 0;
    let (e, end) = walked(Format::Ext, &img, Limits::default());
    end.unwrap();
    let by = |n: &str| e.iter().find(|x| x.name == n).unwrap();
    assert_eq!(
        by("big4k.bin").unsupported,
        Some("file could not be read from the volume")
    );
    assert_eq!(by("p1.bin").data, pat(4, 1025));
    assert_eq!(by("many/file_299.dat").data, pat(1299, 299 % 97));
}

/// A file in an encrypted directory holds ciphertext; it is reported as
/// encrypted.
#[test]
fn an_encrypted_file_is_reported_as_encrypted() {
    let mut img = image("ext4");
    let (ino, _) = ino_of(&img, "tiny.txt");
    // `i_flags`, 32 bytes into the inode: encrypted.
    let at = inode_at(&img, ino) + 32;
    let flags = u32::from_le_bytes(img[at..at + 4].try_into().unwrap()) | 0x800;
    img[at..at + 4].copy_from_slice(&flags.to_le_bytes());
    let e = walk_members(Format::Ext, &img);
    let tiny = e.iter().find(|x| x.name == "tiny.txt").unwrap();
    assert!(tiny.encrypted && tiny.unsupported.is_some() && tiny.data.is_empty());
}

/// What the image records of a file besides its bytes comes with it.
#[test]
fn a_file_comes_with_its_mode() {
    let e = walk_members(Format::Ext, &image("ext4"));
    let tiny = e.iter().find(|x| x.name == "tiny.txt").unwrap();
    assert_eq!(tiny.mode.map(|m| m & 0o170000), Some(0o100000));
    assert!(tiny.mtime.is_some());
}

/// An image cut short is a volume whose structures are not all there: that is
/// said, not read as a smaller volume.
#[test]
fn an_image_cut_short_is_reported() {
    let img = image("ext4");
    let (_, end) = walked(Format::Ext, &img[..40 * 1024], Limits::default());
    assert!(end.unwrap_err().is_corrupt());
}

/// The walk stops at the member limit, as every container does, and the
/// entry past it is not lost without a word: the root with its folders removed
/// holds 10 files.
#[test]
fn a_volume_with_more_entries_than_the_limit_is_walked_to_it_and_stops() {
    let mut img = image("ext4");
    for dir in ["lost+found", "a", "many", "emptydir"] {
        let (_, at) = ino_of(&img, dir);
        img[at..at + 4].fill(0);
    }
    let run = |max: u64| {
        let mut limits = Limits::default();
        limits.max_members = max;
        walked(Format::Ext, &img, limits)
    };
    let (e, end) = run(10);
    end.unwrap();
    assert_eq!(e.len(), 10);
    let (e, end) = run(9);
    assert!(!end.unwrap_err().is_corrupt());
    assert_eq!(e.len(), 9);
}
