//! FAT — reading the filesystem, not carving the sectors.
//!
//! A raw disk is a pile of sectors. Carving finds a file whose magic sits at the
//! start of a contiguous run and misses everything else, so a **fragmented**
//! file — one written into a hole left by a deleted file and continuing past it
//! — comes back as disconnected pieces that will not decompress.
//!
//! The fixture is built to be exactly that case: three files written, the middle
//! one deleted, then a 12 KB payload written so it lands in the 4 KB hole and
//! continues after `c.bin`. Its cluster chain has **two runs**, and the payload
//! is a deflated ZIP, so the EICAR string appears nowhere in the image's bytes.
//! Only following the chain reassembles it.
//!
//! Built with `mtools` (`mformat`/`mcopy`/`mdel`), stored gzipped because a FAT
//! image is mostly empty space.
//!
//! Regenerate with:
//! ```sh
//! mformat -i fragmented.img -C -t 8 -h 2 -s 16 -c 1 ::
//! mcopy -i fragmented.img padA ::/a.bin; mcopy -i fragmented.img padB ::/b.bin
//! mcopy -i fragmented.img padC ::/c.bin; mdel -i fragmented.img ::/b.bin
//! mmd -i fragmented.img ::/sub; mcopy -i fragmented.img payload.zip ::/sub/p.zip
//! gzip -9 fragmented.img
//! ```

use super::extract_each;
use super::fs_tree::{
    assert_streams_alike, assert_tree, image, members as walk_members, tree, walked as fs_walked,
};
use exav_unpack::{Budget, Entry, Format, Limits, detect};

/// `sha256sum` of the ZIP that was copied in, which is what following the
/// cluster chain has to reproduce.
const PAYLOAD: &str = "aa3029a89a5e657f2d4fa85d3c352d348c08d30b04b924417d7e8b2c3a6bb342";

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/fat/fragmented.img.gz",
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
        Format::Fat,
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
fn a_boot_sector_is_recognised_as_a_filesystem_not_a_partition_table() {
    // Both end in `55 AA`. Reading a volume boot record as a partition table
    // used to invent a partition covering the whole image, which then re-detected
    // the same way until the recursion budget was gone.
    assert_eq!(detect(&fixture()), Some(Format::Fat));
}

#[test]
fn a_fragmented_file_is_reassembled_from_its_cluster_chain() {
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
        "the file spans two non-adjacent runs, so anything short of following \
         the chain returns fragments rather than the file"
    );
}

#[test]
fn files_come_back_with_their_directory_paths() {
    let e = members(&fixture());
    let mut names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
    names.sort();
    assert!(
        names.iter().any(|n| n.contains('/')),
        "a file in a subdirectory should carry its path, got {names:?}"
    );
}

#[test]
fn the_payload_is_absent_from_the_raw_image() {
    // Guards the premise: if EICAR were visible in the sectors, a raw scan would
    // find it without reading the filesystem and this fixture would prove
    // nothing about the cluster walk.
    let eicar = exav_unpack::eicar();
    let img = fixture();
    assert!(!img.windows(eicar.len()).any(|w| w == eicar));
}

#[test]
fn a_corrupt_filesystem_is_reported_not_shrugged_off() {
    // The boot sector still says FAT, so the files are there and a real mount
    // would read them; failing to must not read as clean.
    let mut img = fixture();
    // Scribble over the file allocation table itself: the first copy, which
    // begins after the reserved sectors.
    let sector = usize::from(u16::from_le_bytes([img[11], img[12]]));
    let start = usize::from(u16::from_le_bytes([img[14], img[15]])) * sector;
    let len = usize::from(u16::from_le_bytes([img[22], img[23]])) * sector;
    img[start..start + len].fill(0xFF);
    let e = members(&img);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "a file whose chain is gone must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

/// The fixture with the first cluster of the root directory's entry `name`
/// (8.3, padded to 11 bytes) set to `cluster`.
fn with_first_cluster(name: &[u8; 11], cluster: u16) -> Vec<u8> {
    let mut img = fixture();
    let at = img
        .windows(11)
        .position(|w| w == name)
        .unwrap_or_else(|| panic!("no entry {:?}", String::from_utf8_lossy(name)));
    img[at + 26..at + 28].copy_from_slice(&cluster.to_le_bytes());
    img
}

fn walked(blob: &[u8]) -> (Vec<Entry>, Result<Option<()>, exav_unpack::LimitHit>) {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let end = extract_each(
        Format::Fat,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    (out, end)
}

/// Clusters are numbered from 2, and a directory that names cluster 1 has no
/// place to be read from. The rest of the volume is walked, and the walk ends
/// as one over a damaged volume.
#[test]
fn a_directory_at_cluster_1_ends_the_walk_as_damaged_after_the_rest_of_the_volume() {
    let (e, end) = walked(&with_first_cluster(b"SUB        ", 1));
    assert!(end.unwrap_err().is_corrupt());
    let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
    assert!(
        names.contains(&"a.bin") && names.contains(&"c.bin"),
        "{names:?}"
    );
    assert!(!names.iter().any(|n| n.starts_with("sub/")), "{names:?}");
}

/// The same for a file: the others come out, it is reported.
#[test]
fn a_file_at_cluster_1_is_reported_and_the_other_files_come_out() {
    let (e, end) = walked(&with_first_cluster(b"A       BIN", 1));
    end.unwrap_or_else(|h| panic!("the volume was ended: {h:?}"));
    let by = |n: &str| e.iter().find(|x| x.name == n);
    assert!(by("a.bin").is_some_and(|x| x.unsupported.is_some()));
    assert!(by("c.bin").is_some_and(|x| x.unsupported.is_none()));
    assert_eq!(
        by("sub/p.zip").map(|x| sha256_hex(&x.data)).as_deref(),
        Some(PAYLOAD)
    );
}

/// The same tree comes out of FAT12, FAT16 and FAT32, long names included, and
/// of a volume a kernel wrote, which keeps the case of a short name in two flags
/// where the other images have a long name. The deleted entries (pads written
/// first, to fragment the files) and the volume label are not files.
#[test]
fn every_kind_of_fat_reads_the_same_tree() {
    for name in ["fat12", "fat16", "fat32", "fat16_kernel"] {
        let e = walk_members(Format::Fat, &image(name));
        std::panic::catch_unwind(|| assert_tree(&e, &tree(false)))
            .unwrap_or_else(|_| panic!("{name}"));
    }
}

/// A file over the buffer limit is read as it goes, in every kind of FAT, a
/// fragmented one included.
#[test]
fn files_over_the_buffer_limit_are_read_as_they_go() {
    for name in ["fat12", "fat16", "fat32", "fat16_kernel"] {
        assert_streams_alike(Format::Fat, &image(name), 1000);
    }
}

/// The place of the 32-byte directory entry with the short name `name`.
fn entry_of(img: &[u8], name: &[u8; 11]) -> usize {
    img.windows(12)
        .position(|w| w[..11] == name[..] && w[11] & 0x10 != 0)
        .unwrap_or_else(|| panic!("no folder {:?}", String::from_utf8_lossy(name)))
}

/// A folder that names a folder it is in is walked once.
#[test]
fn a_folder_that_names_the_folder_it_is_in_is_walked_once() {
    let mut img = image("fat16");
    let a = entry_of(&img, b"A          ");
    let b = entry_of(&img, b"B          ");
    let first = [img[a + 26], img[a + 27]];
    img[b + 26..b + 28].copy_from_slice(&first);
    let e = walk_members(Format::Fat, &img);
    let mut want = tree(false);
    want.retain(|(p, _)| p != "a/b/c/deep.bin");
    assert_tree(&e, &want);
}

/// A file with a chain that ends before its size does is reported with what
/// there is.
#[test]
fn a_chain_that_ends_early_is_a_file_reported_with_what_it_holds() {
    let mut img = image("fat16");
    // The table begins after the reserved sectors; cluster 3 is the second
    // entry of a file in the first run, and an end of chain makes it the last.
    let e = walk_members(Format::Fat, &img);
    assert!(e.iter().all(|x| x.unsupported.is_none()));
    let reserved = usize::from(u16::from_le_bytes([img[14], img[15]]));
    let table = reserved * usize::from(u16::from_le_bytes([img[11], img[12]]));
    let frag = entry_of_file(&img, b"FRAG    BIN");
    let first = usize::from(u16::from_le_bytes([img[frag + 26], img[frag + 27]]));
    img[table + first * 2..table + first * 2 + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let (e, end) = walked(&img);
    end.unwrap();
    let f = e.iter().find(|x| x.name == "frag.bin").unwrap();
    assert_eq!(
        f.unsupported,
        Some("file could not be read from the volume")
    );
    assert!(!f.data.is_empty() && f.data.len() < 100000);
}

fn entry_of_file(img: &[u8], name: &[u8; 11]) -> usize {
    img.windows(12)
        .position(|w| w[..11] == name[..] && w[11] & 0x10 == 0)
        .unwrap_or_else(|| panic!("no file {:?}", String::from_utf8_lossy(name)))
}

/// Entries past the member limit are not lost without a word.
#[test]
fn a_directory_longer_than_the_member_limit_stops_the_walk() {
    let img = image("fat16");
    // The root holds 10 files and 3 folders, `many` 300 files.
    let run = |max: u64| {
        let mut limits = Limits::default();
        limits.max_members = max;
        fs_walked(Format::Fat, &img, limits)
    };
    let (e, end) = run(1000);
    end.unwrap();
    assert_eq!(e.len(), 310);
    let (e, end) = run(100);
    assert!(!end.unwrap_err().is_corrupt());
    assert!(!e.is_empty() && e.len() <= 100);
}

/// An image cut short is a volume whose structures are not all there.
#[test]
fn an_image_cut_short_is_reported() {
    let img = image("fat16");
    let (_, end) = fs_walked(Format::Fat, &img[..2048], Limits::default());
    assert!(end.unwrap_err().is_corrupt());
    // Cut where the files are, the volume opens and the files are partial.
    let (e, end) = fs_walked(Format::Fat, &img[..200 * 1024], Limits::default());
    let _ = end;
    assert!(e.iter().any(|x| x.unsupported.is_some()));
}

/// What a file records of when it was written is kept, as the wall-clock time
/// a FAT volume records it as.
#[test]
fn a_file_comes_with_the_time_it_was_written() {
    let e = walk_members(Format::Fat, &image("fat16_kernel"));
    let tiny = e.iter().find(|x| x.name == "tiny.txt").unwrap();
    assert!(matches!(
        tiny.mtime,
        Some(exav_unpack::Mtime::Local { year: 2026, .. })
    ));
}
