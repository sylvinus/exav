//! UDF: the filesystem on DVDs, Blu-rays and most `.iso` files written today.
//!
//! Two shapes matter. A **UDF-only** image carries no ISO 9660 tree at all, so
//! without UDF support every file in it is invisible while Windows and macOS
//! both mount it on double-click. A **bridge** image carries both filesystems
//! over the same extents, where the risk is the opposite one: walking both trees
//! naively scans every file twice.
//!
//! The expected digests are `7zz x` output on the same fixtures (7-Zip's, not
//! this crate's). A filesystem walker validated against its own writer can agree
//! on a shared misreading of the spec.
//!
//! Regenerate with:
//! ```sh
//! genisoimage -udf -o bridge.iso -V TEST udfsrc/     # both filesystems
//! # then blank the `CD001` identifiers in sectors 16..19 to leave UDF alone
//! gzip -9 bridge.iso udf_only.iso
//! ```
//!
//! Stored gzipped because a UDF volume's descriptor sequences put the file data
//! past sector 256, making even a three-file image ~900 KiB of mostly zeroes.
//! The bytes inside are genisoimage's.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits, detect};

/// `sha256sum` of what `7zz x` writes for each member.
const README_SHA256: &str = "8d2f3443b4461106fa29ee57260e553ee6acb25cc0a00a28a777013d2420985e";
const BIG_SHA256: &str = "c33e271d1d90b8d5615d100ea4a90d2f83adf72f0805935142f179b8c3838a73";
const PAYLOAD_SHA256: &str = "13d029085fab073b6c20dd01a423c97e324dc430ca8186795a2a367a23f11143";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/udf/{name}", env!("CARGO_MANIFEST_DIR"));
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
        Format::Iso,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

/// What a [`exav_unpack::walk`] visitor reading each member as it comes sees,
/// as `(name, sha256, unsupported)`.
fn streamed(blob: &[u8]) -> Vec<(String, String, Option<&'static str>)> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = exav_unpack::walk(
        Format::Iso,
        &blob,
        &mut b,
        &mut |m: &exav_unpack::MemberMeta,
              content: Option<exav_unpack::Member<'_>>,
              _: &mut Budget| {
            let data = match content {
                None => Vec::new(),
                Some(exav_unpack::Member::Bytes(d)) => d,
                Some(exav_unpack::Member::Stream(r)) => {
                    let mut d = Vec::new();
                    std::io::Read::read_to_end(r, &mut d).expect("read member");
                    d
                }
            };
            out.push((m.name.clone(), sha256_hex(&data), m.unsupported));
            None::<()>
        },
    );
    out
}

#[test]
fn the_streamed_walk_yields_what_the_buffered_one_does() {
    // Every ISO the scanner meets goes through the streamed walk, at any depth
    // and any size. It used to walk ISO 9660 only, so a UDF-only image
    // streamed as an empty container.
    let mut damaged = fixture("udf_only.iso.gz");
    let sectors = damaged.len() / 2048;
    for s in [256, sectors - 1, sectors - 257] {
        damaged[s * 2048..s * 2048 + 16].fill(0);
    }
    for (name, blob) in [
        ("udf_only", fixture("udf_only.iso.gz")),
        ("bridge", fixture("bridge.iso.gz")),
        ("damaged", damaged),
        ("metadata", fixture("metadata.iso.gz")),
        ("mirror_only", mirror_only()),
    ] {
        let buffered: Vec<_> = members(&blob)
            .iter()
            .map(|e| (e.name.clone(), sha256_hex(&e.data), e.unsupported))
            .collect();
        assert!(!buffered.is_empty(), "{name}: the fixture yields nothing");
        assert_eq!(streamed(&blob), buffered, "{name}");
    }
}

#[test]
fn a_udf_only_image_is_recognised_at_all() {
    // It has no `CD001`, so nothing but the UDF volume recognition sequence
    // identifies it. Falling through to "unknown blob" would leave every file
    // inside unscanned while the image still reported clean.
    let blob = fixture("udf_only.iso.gz");
    assert_eq!(detect(&blob), Some(Format::Iso));
}

#[test]
fn a_udf_only_image_yields_every_file_7zip_does() {
    assert_every_file(&members(&fixture("udf_only.iso.gz")));
}

/// `metadata.iso.gz` with its metadata file's entry blanked, leaving the mirror.
fn mirror_only() -> Vec<u8> {
    let mut blob = fixture("metadata.iso.gz");
    blob[257 * 2048..257 * 2048 + 16].fill(0);
    blob
}

#[test]
fn a_metadata_partition_image_yields_every_file() {
    // UDF 2.50 and later keep the whole tree, file entries and directories, in
    // a metadata partition: a file whose blocks are addressed through their own
    // extents. Written by `fixtures/udf/make_metadata_iso.py`, read back by the
    // Linux kernel with the same digests as `7zz x` gives for `udf_only`.
    assert_every_file(&members(&fixture("metadata.iso.gz")));
}

#[test]
fn the_mirror_serves_when_the_metadata_file_is_unreadable() {
    assert_every_file(&members(&mirror_only()));
}

/// The three files of the UDF fixtures, and nothing reported unreadable.
fn assert_every_file(e: &[Entry]) {
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy UDF image must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );

    let mut got: Vec<(String, String)> = e
        .iter()
        .map(|x| (x.name.clone(), sha256_hex(&x.data)))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("nested/big.bin".to_string(), BIG_SHA256.to_string()),
            (
                "nested/deeper/payload.zip".to_string(),
                PAYLOAD_SHA256.to_string()
            ),
            ("readme.txt".to_string(), README_SHA256.to_string()),
        ],
        "names and contents must match `7zz x`, including the nested paths and \
         the file that spans several blocks"
    );
}

#[test]
fn a_bridge_image_scans_each_file_once() {
    // Both filesystems name the same extents. Walking them independently would
    // hand the scanner every file twice, doubling the work on the commonest
    // kind of `.iso` there is.
    let e = members(&fixture("bridge.iso.gz"));
    assert_eq!(
        e.len(),
        3,
        "expected one member per file, got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    let mut digests: Vec<String> = e.iter().map(|x| sha256_hex(&x.data)).collect();
    digests.sort();
    let mut want = vec![
        BIG_SHA256.to_string(),
        PAYLOAD_SHA256.to_string(),
        README_SHA256.to_string(),
    ];
    want.sort();
    assert_eq!(digests, want);
}

#[test]
fn a_udf_volume_that_cannot_be_read_says_so() {
    // Blanking every anchor volume descriptor (sector 256 and the two copies
    // at the end of the volume) leaves an image that announces UDF in its
    // recognition sequence and then gives no way in. Every file is still there;
    // exav simply cannot reach them, which is exactly the case that must never
    // pass as clean.
    let mut blob = fixture("udf_only.iso.gz");
    let sectors = blob.len() / 2048;
    for s in [256, sectors - 1, sectors - 257] {
        blob[s * 2048..s * 2048 + 16].fill(0);
    }

    let e = members(&blob);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "an unreadable UDF volume must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

/// The image of `udf_only` has 3 directories and 3 files. The sector of its
/// File Entry for `nested/big.bin` (20,000 bytes in one extent), where the
/// partition starts, and where the file entries of the directories are.
const BIG_ENTRY_SECTOR: usize = 266;
const PARTITION_START: usize = 257;

/// `udf_only` with the allocation descriptors of `big.bin` declared `bytes`
/// long: its one extent, then zero-length ones.
fn with_descriptor_bytes(bytes: u32) -> Vec<u8> {
    let mut blob = fixture("udf_only.iso.gz");
    let l_ad = BIG_ENTRY_SECTOR * 2048 + 172;
    assert_eq!(blob[l_ad..l_ad + 4], 8u32.to_le_bytes(), "the entry moved");
    blob[l_ad..l_ad + 4].copy_from_slice(&bytes.to_le_bytes());
    blob
}

fn walked_under(
    blob: &[u8],
    limits: Limits,
) -> (Vec<Entry>, Result<Option<()>, exav_unpack::LimitHit>) {
    super::fs_tree::walked(Format::Iso, blob, limits)
}

/// Each directory read is one member against `max_members`, as each file is,
/// and its bytes are charged to the scan: directories can overlap on an image,
/// so how many of them are read is no measure of its size.
#[test]
fn the_directories_of_the_tree_are_counted_and_charged() {
    let blob = fixture("udf_only.iso.gz");
    let counted = |max_members: u64| {
        let mut limits = Limits::default();
        limits.max_members = max_members;
        walked_under(&blob, limits)
    };
    // Three directories and three files.
    let (e, end) = counted(6);
    end.unwrap();
    assert_eq!(e.len(), 3);
    let (_, end) = counted(5);
    let hit = end.expect_err("the directories were not counted");
    assert_eq!(hit.kind, exav_unpack::LimitKind::MaxFiles, "{hit}");
    let (e, end) = counted(u64::MAX);
    end.unwrap();
    assert_eq!(e.len(), 3);

    // The root directory is 140 bytes: a scan budget below it stops the walk
    // before any member.
    let mut limits = Limits::default();
    limits.max_scanned_bytes = 100;
    let (e, end) = walked_under(&blob, limits);
    let hit = end.expect_err("the bytes of the directories were not charged");
    assert_eq!(hit.kind, exav_unpack::LimitKind::MaxScanSize, "{hit}");
    assert!(e.is_empty());
}

/// The descriptors of one file entry are read up to `max_members` of them, and
/// up to the buffer limit in bytes. A list longer than that is cut where it
/// is and reported, the file as far as it was followed still given.
#[test]
fn a_list_of_allocation_descriptors_is_bounded_by_the_member_limit_and_the_buffer_limit() {
    // 200 short descriptors of 8 bytes: 1,600 bytes.
    let blob = with_descriptor_bytes(1600);
    let under = |max_members: u64, held: u64| {
        let mut limits = Limits::default();
        limits.max_members = max_members;
        limits.max_buffer_bytes = held;
        let (e, end) = walked_under(&blob, limits);
        end.unwrap();
        let big = e
            .iter()
            .find(|x| x.name == "nested/big.bin")
            .unwrap()
            .data
            .len();
        let cut = e
            .iter()
            .filter(|x| {
                x.unsupported
                    .is_some_and(|r| r.contains("allocation descriptors"))
            })
            .count();
        (big, cut)
    };
    let big = 20_000;
    // Exactly the descriptors there are: nothing is cut.
    assert_eq!(under(200, 1 << 30), (big, 0));
    assert_eq!(under(u64::MAX, u64::MAX), (big, 0));
    // One too few.
    assert_eq!(under(199, 1 << 30), (big, 1));
    // The buffer limit holds the same bytes.
    assert_eq!(under(u64::MAX, 1600), (big, 0));
    assert_eq!(under(u64::MAX, 1599), (big, 1));
}

/// A continuation that points back at a list already read ends the list,
/// reported, whatever the limits: with none, it would be followed for ever.
#[test]
fn a_continuation_that_loops_ends_the_list_with_a_report() {
    let mut blob = fixture("udf_only.iso.gz");
    // The entry's one descriptor becomes a continuation to a block that has
    // the extent, then a continuation to itself. The list of a continuation
    // starts 24 bytes into its block.
    let block = 12;
    let at = (PARTITION_START + block) * 2048;
    assert!(
        blob[at..at + 2048].iter().all(|&b| b == 0),
        "the block is used"
    );
    let entry = BIG_ENTRY_SECTOR * 2048;
    let extent: [u8; 8] = blob[entry + 176..entry + 184].try_into().unwrap();
    let continuation = |lbn: u32| {
        let mut ad = (40u32 | 3 << 30).to_le_bytes().to_vec();
        ad.extend_from_slice(&lbn.to_le_bytes());
        ad
    };
    blob[entry + 176..entry + 184].copy_from_slice(&continuation(block as u32));
    blob[at..at + 2].copy_from_slice(&258u16.to_le_bytes());
    blob[at + 24..at + 32].copy_from_slice(&extent);
    blob[at + 32..at + 40].copy_from_slice(&continuation(block as u32));

    let mut limits = Limits::default();
    limits.max_members = u64::MAX;
    limits.max_buffer_bytes = u64::MAX;
    let (tx, rx) = std::sync::mpsc::channel();
    // A walk that does not end is the failure: the test must not hang on it.
    std::thread::spawn(move || {
        let (e, end) = walked_under(&blob, limits);
        let _ = tx.send((e, end.map(|_| ()).map_err(|h| h.reason)));
    });
    let (e, end) = rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the walk of a looping continuation did not end");
    end.unwrap();
    let big = e.iter().find(|x| x.name == "nested/big.bin").unwrap();
    assert_eq!(big.data.len(), 20_000);
    assert!(
        e.iter().any(|x| x
            .unsupported
            .is_some_and(|r| r.contains("allocation descriptors"))),
        "the loop was not reported"
    );
}
