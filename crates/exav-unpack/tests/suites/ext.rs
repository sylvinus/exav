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

use exav_unpack::{detect, extract_each, Budget, Entry, Format, Limits};

/// `sha256sum` of the ZIP that was written in, which is what following the
/// extent tree has to reproduce.
const PAYLOAD: &str = "d61da8b0c3cd1d5ffa812601aae787c81a7424850c4dca15c27e593f8f92fcc8";

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/ext/fragmented.img.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
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
    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
    let img = fixture();
    assert!(!img.windows(EICAR.len()).any(|w| w == EICAR));
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
    let e = members(&img);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "an image that cannot be walked must say so, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_image_past_the_buffer_budget_is_reported_not_skipped() {
    // The reader owns its bytes, so the image is copied once. An image too
    // large to copy is a gap the operator must be able to see.
    let img = fixture();
    let mut b = Budget::new(Limits {
        max_buffer_bytes: 1024,
        ..Limits::default()
    });
    let mut out = Vec::new();
    let _ = extract_each(
        Format::Ext,
        &img,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    assert!(
        out.iter().any(|x| x.unsupported.is_some()),
        "an image over the budget must be reported, got {:?}",
        out.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
