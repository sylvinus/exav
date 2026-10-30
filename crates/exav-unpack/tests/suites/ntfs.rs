//! NTFS — reading files out of the master file table.
//!
//! VHD and VHDX are Windows-native, so a disk image aimed at a Windows victim
//! holds NTFS. A raw carve of the volume finds a file only where its magic
//! starts a contiguous run, which leaves a gap an attacker chooses the size of:
//! fragment a file and the carve sees pieces.
//!
//! The fixture is a real volume built with `mkntfs` and filled with `ntfscp`,
//! then edited so `payload.zip` occupies **two non-adjacent runs**. The edit is
//! not taken on trust — `ntfscat` reads the edited volume back to the same
//! digest, so an independent NTFS implementation agrees it is a valid two-run
//! file. The payload is a deflated ZIP, so EICAR appears nowhere in the volume's
//! bytes and only reassembly reaches it.
//!
//! Stored gzipped: an NTFS volume carries megabytes of `$LogFile` and `$UpCase`.
//!
//! Regenerate with:
//! ```sh
//! mkntfs -F -q -c 4096 -L exavtest ntfs.img
//! ntfscp ntfs.img payload.zip /payload.zip     # plus small.txt, eicar.com
//! # then split payload.zip's single run in two and re-apply the MFT fix-ups
//! ```

use super::extract_each;
use super::fs_tree::{assert_streams_alike, came};
use exav_unpack::{Budget, Entry, Format, Limits, detect};

/// `sha256sum` of what `ntfscat` returns for each file.
const PAYLOAD: &str = "49c7e4f4b184954a212c78c87c17705cd4c16f0b8c83a5cd6a750369c47957c5";
const SMALL: &str = "725445a66654be611d0a1c073b63c6d40bce0bb592b61e71db41f8de2cce6146";
const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// The two-run list for `payload.zip`: four clusters, then four more one cluster
/// further on. Unique in the image.
const RUNLIST: [u8; 8] = [0x21, 0x04, 0x00, 0x0c, 0x11, 0x04, 0x04, 0x00];

pub(super) fn fixture() -> Vec<u8> {
    gunzipped("fragmented.img.gz")
}

fn gunzipped(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/ntfs/{name}", env!("CARGO_MANIFEST_DIR"));
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
        Format::Ntfs,
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
fn a_volume_is_recognised_from_its_boot_sector() {
    assert_eq!(detect(&fixture()), Some(Format::Ntfs));
}

#[test]
fn a_fragmented_file_is_reassembled_from_its_data_runs() {
    let e = members(&fixture());
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "a healthy volume must not report anything unreadable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let p = e
        .iter()
        .find(|x| x.name == "payload.zip")
        .unwrap_or_else(|| {
            panic!(
                "the payload must be found; got {:?}",
                e.iter().map(|x| &x.name).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        sha256_hex(&p.data),
        PAYLOAD,
        "the file spans two non-adjacent runs, so anything short of following \
         both returns fragments — and `ntfscat` returns this same digest"
    );
}

#[test]
fn a_resident_file_is_read_from_inside_its_record() {
    // A file small enough lives in the MFT record itself with no runs at all,
    // which is a different code path from every other file here.
    let e = members(&fixture());
    let s = e
        .iter()
        .find(|x| x.name == "small.txt")
        .expect("the resident file must be found");
    assert_eq!(sha256_hex(&s.data), SMALL);
}

#[test]
fn the_filesystems_own_metadata_is_not_emitted() {
    // `$MFT`, `$LogFile`, `$UpCase` and friends are filesystem internals, and
    // emitting them would spend the budget on megabytes of them. Nothing is lost:
    // the volume's raw bytes are pattern-scanned before this walk runs.
    let e = members(&fixture());
    assert!(
        !e.iter().any(|x| x.name.starts_with('$')),
        "metadata files should not be emitted, got {:?}",
        e.iter().map(|x| &x.name).collect::<Vec<_>>()
    );
    assert_eq!(e.len(), 3, "exactly the three user files");
}

#[test]
fn runs_that_do_not_cover_the_declared_size_are_reported_not_truncated() {
    // The failure mode that matters most. If the runs come up short — because
    // they were followed wrongly, or spill into an MFT record exav did not
    // reach — emitting what was gathered would hand the scanner a *prefix* of
    // the file and call it the file. A prefix that happens to exclude the
    // payload scans perfectly clean.
    //
    // Shrinking the first run from four clusters to two leaves the runs covering
    // six of eight, with the declared size unchanged.
    let mut img = fixture();
    let at = img
        .windows(RUNLIST.len())
        .position(|w| w == RUNLIST)
        .expect("the two-run list should be in the fixture");
    img[at + 1] = 0x02;

    let e = members(&img);
    let p = e
        .iter()
        .find(|x| x.name == "payload.zip")
        .expect("the file should still be listed");
    assert!(
        p.unsupported.is_some(),
        "a short read must be reported, not emitted as the whole file"
    );
    assert!(
        p.data.is_empty(),
        "and no partial content should be passed off as the file"
    );
}

#[test]
fn a_fragmented_file_over_the_buffer_limit_is_read_as_it_goes_across_both_runs() {
    let img = fixture();
    assert_streams_alike(Format::Ntfs, &img, 1000);
    let (e, end) = came(Format::Ntfs, &img, 1000);
    end.unwrap();
    let p = e.iter().find(|x| x.name == "payload.zip").unwrap();
    assert!(p.streamed, "the payload is past the limit, so not held");
    assert_eq!(sha256_hex(&p.data), PAYLOAD);
    assert_eq!(p.read_error, None);
}

#[test]
fn runs_that_do_not_cover_the_size_of_a_file_read_as_it_goes_are_reported_with_what_there_is() {
    let mut img = fixture();
    let at = img
        .windows(RUNLIST.len())
        .position(|w| w == RUNLIST)
        .expect("the two-run list should be in the fixture");
    img[at + 1] = 0x02;
    let (e, end) = came(Format::Ntfs, &img, 1000);
    end.unwrap();
    // Reported first, then the file, which ends in an error where its runs do.
    let at = e.iter().position(|x| x.name == "payload.zip").unwrap();
    assert!(e[at].unsupported.is_some(), "the shortfall is reported");
    let stream = &e[at + 1];
    assert!(stream.streamed && stream.name == "payload.zip");
    assert!(stream.read_error.is_some(), "and the read says it stops");
    assert_eq!(
        stream.data.len(),
        6 * 4096,
        "with the six clusters there are"
    );
}

// A file fragmented past what its MFT record holds: the runs continue in
// extension records, and the `$ATTRIBUTE_LIST` that names them is itself outside
// the record (non-resident). `attribute_list.img.gz` is a 14 MiB volume made by
// `ntfs-3g`, not edited afterwards:
//
//   mkntfs -F -q -c 1024 -L exavtest vol.img
//   ntfs-3g vol.img /mnt                          # then, as root, in /mnt:
//   write 3000 files of 2000 bytes, delete every other one, then write
//   payload.txt: lines "line %07d fragmented across the holes\n" until the
//   volume is full
//
// The file is the first 5,280,759 bytes of those lines, in the holes and the
// tail of the volume. `ntfscat` returns the same digest; `ntfsinfo -v` shows
// the list non-resident and the data runs in extension records.
const ATTRIBUTE_LIST_PAYLOAD: &str =
    "8b315ad3f77c9f3ce1dc711c99eb3e2c8240bf7881ee373cfe92d4a5eec21702";

#[test]
fn a_file_whose_runs_are_named_by_an_attribute_list_is_read_whole() {
    let e = members(&gunzipped("attribute_list.img.gz"));
    assert!(
        e.iter().all(|x| x.unsupported.is_none()),
        "got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    let p = e
        .iter()
        .find(|x| x.name == "payload.txt")
        .expect("the fragmented file must be found");
    assert_eq!(p.data.len(), 5_280_759);
    assert_eq!(sha256_hex(&p.data), ATTRIBUTE_LIST_PAYLOAD);
}

/// The byte offset in `img` of the size fields of the non-resident
/// `$ATTRIBUTE_LIST` (`real_size` at +0x30) of the one file that has one.
fn attribute_list_size_at(img: &[u8]) -> usize {
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([img[at], img[at + 1]]));
    let cluster = u16_at(11) * usize::from(img[13]);
    let mft = u64::from_le_bytes(img[0x30..0x38].try_into().unwrap()) as usize * cluster;
    let mut found = Vec::new();
    for rec in (mft + 16 * 1024..mft + 200 * 1024).step_by(1024) {
        // Files only: the root directory of this volume has a list as well.
        if &img[rec..rec + 4] != b"FILE" || u16_at(rec + 22) & 2 != 0 {
            continue;
        }
        let mut off = rec + u16_at(rec + 20);
        while off + 8 <= rec + 1024 {
            let ty = u32::from_le_bytes(img[off..off + 4].try_into().unwrap());
            let len = u32::from_le_bytes(img[off + 4..off + 8].try_into().unwrap()) as usize;
            if ty == 0xFFFF_FFFF || len < 16 {
                break;
            }
            if ty == 0x20 && img[off + 8] != 0 {
                found.push(off + 0x30);
            }
            off += len;
        }
    }
    assert_eq!(found.len(), 1, "one non-resident attribute list expected");
    found[0]
}

#[test]
fn an_attribute_list_that_reads_short_is_reported_not_half_used() {
    // The list claims 2048 bytes and its one cluster holds 1024: a list read
    // short would drop the extents it names, and the file would be emitted as
    // its first extent alone. The size is part of the record, outside the
    // update-sequence positions (the last two bytes of each 512-byte sector).
    let mut img = gunzipped("attribute_list.img.gz");
    let at = attribute_list_size_at(&img);
    assert!(at % 512 < 500, "the size field must not sit on a fix-up");
    assert_eq!(
        u64::from_le_bytes(img[at..at + 8].try_into().unwrap()),
        224,
        "the list as written"
    );
    img[at..at + 8].copy_from_slice(&2048u64.to_le_bytes());

    let e = members(&img);
    // The list also names the extension record that holds the file's name, so
    // without it the file is found by its record, not by "payload.txt".
    let payload: Vec<_> = e
        .iter()
        .filter(|x| x.name == "payload.txt" || x.name.starts_with("<mft-record-"))
        .collect();
    assert!(
        payload.iter().any(|x| x.unsupported.is_some()),
        "a short list must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
    assert!(
        !payload
            .iter()
            .any(|x| x.unsupported.is_none() && sha256_hex(&x.data) == ATTRIBUTE_LIST_PAYLOAD),
        "and the whole file must not be passed off from a half-read list"
    );
}

/// A volume of 512-byte clusters and 1 MiB records (the format's largest)
/// whose record 16 is a file with a non-resident `$ATTRIBUTE_LIST` of `entries`
/// entries of type `kind`, all naming record 2 (a valid file of 1 MiB). 39 MB,
/// made in memory; the list is the one bytes a reviewer's generator wrote
/// (`entries * 26` of them).
fn volume_with_a_list(entries: usize, kind: u32) -> Vec<u8> {
    const CLUSTER: usize = 512;
    const REC: usize = 1 << 20;
    const USA: usize = 0x30;
    let attr_off = (USA + 2 * (REC / CLUSTER + 1) + 7) & !7;
    let list_len = entries * 26;
    let (list_at, mft_at, rec2_data, rec16_data) = (60_000usize, 5usize, 70_000usize, 71_000usize);
    let mft_bytes = 17 * 1024 * 1024;
    let mut vol = vec![0u8; (72_000 + 4096) * CLUSTER];
    vol[..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    vol[3..11].copy_from_slice(b"NTFS    ");
    vol[11..13].copy_from_slice(&512u16.to_le_bytes());
    vol[13] = 1;
    vol[0x30..0x38].copy_from_slice(&(mft_at as u64).to_le_bytes());
    vol[0x40] = 0xEC;
    vol[510..512].copy_from_slice(&[0x55, 0xAA]);

    for k in 0..entries {
        let at = list_at * CLUSTER + k * 26;
        vol[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        vol[at + 4..at + 6].copy_from_slice(&26u16.to_le_bytes());
        vol[at + 8..at + 16].copy_from_slice(&(k as u64).to_le_bytes());
        vol[at + 16..at + 24].copy_from_slice(&2u64.to_le_bytes());
    }

    let run = |lcn: usize, clusters: usize| {
        let mut r = vec![0x33];
        r.extend_from_slice(&clusters.to_le_bytes()[..3]);
        r.extend_from_slice(&lcn.to_le_bytes()[..3]);
        r.push(0);
        r
    };
    // A non-resident attribute at `off` of the record; its length.
    let attribute = |rec: &mut Vec<u8>, off: usize, ty: u32, size: usize, runs: &[u8]| {
        let len = 64 + runs.len();
        rec[off..off + 4].copy_from_slice(&ty.to_le_bytes());
        rec[off + 4..off + 6].copy_from_slice(&(len as u16).to_le_bytes());
        rec[off + 8] = 1;
        rec[off + 0x18..off + 0x20].copy_from_slice(&(size.div_ceil(CLUSTER) as u64).to_le_bytes());
        rec[off + 0x20..off + 0x22].copy_from_slice(&64u16.to_le_bytes());
        rec[off + 0x28..off + 0x30].copy_from_slice(&(size as u64).to_le_bytes());
        rec[off + 0x30..off + 0x38].copy_from_slice(&(size as u64).to_le_bytes());
        rec[off + 0x38..off + 0x40].copy_from_slice(&(size as u64).to_le_bytes());
        rec[off + 64..off + len].copy_from_slice(runs);
        len
    };
    let mut record = |n: usize, attrs: &[(u32, usize, Vec<u8>)]| {
        let mut r = vec![0u8; REC];
        r[..4].copy_from_slice(b"FILE");
        r[0x14..0x16].copy_from_slice(&(attr_off as u16).to_le_bytes());
        r[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
        r[0x18..0x1C].copy_from_slice(&(REC as u32).to_le_bytes());
        r[0x1C..0x20].copy_from_slice(&(REC as u32).to_le_bytes());
        let mut off = attr_off;
        for (ty, size, runs) in attrs {
            off += attribute(&mut r, off, *ty, *size, runs);
        }
        // The update sequence: its number at the start, and at the end of
        // each sector (the values they replace are zeros here).
        let count = REC / CLUSTER + 1;
        r[4..6].copy_from_slice(&(USA as u16).to_le_bytes());
        r[6..8].copy_from_slice(&(count as u16).to_le_bytes());
        r[USA..USA + 2].copy_from_slice(&[0xAA, 0xBB]);
        for i in 1..count {
            r[i * CLUSTER - 2..i * CLUSTER].copy_from_slice(&[0xAA, 0xBB]);
        }
        let at = mft_at * CLUSTER + n * REC;
        vol[at..at + REC].copy_from_slice(&r);
    };
    record(0, &[(0x80, mft_bytes, run(mft_at, mft_bytes / CLUSTER))]);
    record(2, &[(0x80, 1 << 20, run(rec2_data, 2048))]);
    record(
        16,
        &[
            (0x80, 1 << 15, run(rec16_data, 64)),
            (0x20, list_len, run(list_at, list_len.div_ceil(CLUSTER))),
        ],
    );
    vol
}

/// One record named by tens of thousands of list entries was read, and its
/// fix-ups applied, once for each: 40,000 entries took 2 s, 160,000 took 8 s
/// in a release build, and a 256 MiB list (the most a volume may give) about
/// 13 minutes. Read once, it costs what one read does.
#[test]
fn a_record_named_by_a_list_thousands_of_times_is_read_once() {
    for kind in [0x30, 0x80] {
        let start = std::time::Instant::now();
        let e = members(&volume_with_a_list(40_000, kind));
        assert!(
            e.iter()
                .any(|x| x.name.starts_with("<mft-record-") && x.unsupported.is_none()),
            "kind {kind:#x}: {:?}",
            e.iter()
                .map(|x| (&x.name, x.unsupported))
                .collect::<Vec<_>>()
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "kind {kind:#x}: {:?}",
            start.elapsed()
        );
    }
}

/// A list that names more extents than a file has is not followed, and the file
/// is reported as not read whole, never passed off as its first extent.
#[test]
fn a_list_naming_more_extents_than_exav_follows_is_reported() {
    let start = std::time::Instant::now();
    let e = members(&volume_with_a_list(70_000, 0x80));
    let file = e
        .iter()
        .find(|x| x.name.starts_with("<mft-record-"))
        .unwrap();
    assert!(
        file.unsupported.is_some_and(|r| r.contains("more extents")),
        "{:?}",
        file.unsupported
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn the_payload_is_absent_from_the_raw_volume() {
    // Guards the premise: if EICAR were visible in the sectors, a raw scan would
    // find it without reading the filesystem and none of this would be proven.
    let eicar_bytes = exav_unpack::eicar();
    let img = fixture();
    // `eicar.com` itself is stored in the clear, so search only for the copy
    // inside the deflated ZIP by checking it appears exactly once.
    let hits = img
        .windows(eicar_bytes.len())
        .filter(|w| *w == eicar_bytes)
        .count();
    assert_eq!(
        hits, 1,
        "only the plain eicar.com should be visible; the zipped copy must not be"
    );
    let e = members(&img);
    let z = e.iter().find(|x| x.name == "payload.zip").expect("payload");
    assert_eq!(sha256_hex(&z.data), PAYLOAD);
    let plain = e.iter().find(|x| x.name == "eicar.com").expect("eicar");
    assert_eq!(sha256_hex(&plain.data), EICAR);
}

/// A volume of 512-byte clusters and 1,024-byte records whose record 16 is a
/// file with a non-resident `$ATTRIBUTE_LIST` naming `records` records, each
/// holding the next extent of its `$DATA`: `runs_each` runs of one cluster.
/// As [`volume_with_a_list`], made in memory.
fn volume_with_extents(records: usize, runs_each: usize) -> Vec<u8> {
    const CLUSTER: usize = 512;
    const REC: usize = 1024;
    const USA: usize = 0x30;
    const FIRST: usize = 17;
    let attr_off = (USA + 2 * (REC / CLUSTER + 1) + 7) & !7;
    let list_len = records * 26;
    let mft_at = 5usize;
    let mft_bytes = (FIRST + records) * REC;
    let list_at = mft_at + mft_bytes.div_ceil(CLUSTER) + 8;
    let mut vol = vec![0u8; (list_at + list_len.div_ceil(CLUSTER) + 8) * CLUSTER];
    vol[..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    vol[3..11].copy_from_slice(b"NTFS    ");
    vol[11..13].copy_from_slice(&512u16.to_le_bytes());
    vol[13] = 1;
    vol[0x30..0x38].copy_from_slice(&(mft_at as u64).to_le_bytes());
    vol[0x40] = 0xF6;
    vol[510..512].copy_from_slice(&[0x55, 0xAA]);
    assert!(mft_at * CLUSTER + mft_bytes <= list_at * CLUSTER);

    for k in 0..records {
        let at = list_at * CLUSTER + k * 26;
        vol[at..at + 4].copy_from_slice(&0x80u32.to_le_bytes());
        vol[at + 4..at + 6].copy_from_slice(&26u16.to_le_bytes());
        vol[at + 8..at + 16].copy_from_slice(&((k * runs_each) as u64).to_le_bytes());
        vol[at + 16..at + 24].copy_from_slice(&((FIRST + k) as u64).to_le_bytes());
    }

    // `count` runs of one cluster, each a step on from the one before.
    let run = |lcn: usize, clusters: usize, count: usize| {
        let mut r = vec![0x33];
        r.extend_from_slice(&clusters.to_le_bytes()[..3]);
        r.extend_from_slice(&lcn.to_le_bytes()[..3]);
        for _ in 1..count {
            r.extend_from_slice(&[0x11, 1, 1]);
        }
        r.push(0);
        r
    };
    // A record of the non-resident attributes `(type, starting VCN, size, runs)`.
    let mut record = |n: usize, attrs: &[(u32, u64, usize, Vec<u8>)]| {
        let mut r = vec![0u8; REC];
        r[..4].copy_from_slice(b"FILE");
        r[0x14..0x16].copy_from_slice(&(attr_off as u16).to_le_bytes());
        r[0x16..0x18].copy_from_slice(&1u16.to_le_bytes());
        r[0x18..0x1C].copy_from_slice(&(REC as u32).to_le_bytes());
        r[0x1C..0x20].copy_from_slice(&(REC as u32).to_le_bytes());
        let mut off = attr_off;
        for (ty, vcn, size, runs) in attrs {
            let len = 64 + runs.len();
            r[off..off + 4].copy_from_slice(&ty.to_le_bytes());
            r[off + 4..off + 6].copy_from_slice(&(len as u16).to_le_bytes());
            r[off + 8] = 1;
            r[off + 0x10..off + 0x18].copy_from_slice(&vcn.to_le_bytes());
            r[off + 0x18..off + 0x20]
                .copy_from_slice(&(size.div_ceil(CLUSTER) as u64).to_le_bytes());
            r[off + 0x20..off + 0x22].copy_from_slice(&64u16.to_le_bytes());
            for at in [0x28, 0x30, 0x38] {
                r[off + at..off + at + 8].copy_from_slice(&(*size as u64).to_le_bytes());
            }
            r[off + 64..off + len].copy_from_slice(runs);
            off += len;
        }
        r[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let count = REC / CLUSTER + 1;
        r[4..6].copy_from_slice(&(USA as u16).to_le_bytes());
        r[6..8].copy_from_slice(&(count as u16).to_le_bytes());
        r[USA..USA + 2].copy_from_slice(&[0xAA, 0xBB]);
        for i in 1..count {
            // What the sector ends with is kept in the update sequence array.
            let kept = [r[i * CLUSTER - 2], r[i * CLUSTER - 1]];
            r[USA + 2 * i..USA + 2 * i + 2].copy_from_slice(&kept);
            r[i * CLUSTER - 2..i * CLUSTER].copy_from_slice(&[0xAA, 0xBB]);
        }
        let at = mft_at * CLUSTER + n * REC;
        vol[at..at + REC].copy_from_slice(&r);
    };
    record(
        0,
        &[(0x80, 0, mft_bytes, run(mft_at, mft_bytes / CLUSTER, 1))],
    );
    record(
        16,
        &[
            (0x80, 0, 16 * CLUSTER, run(10, 16, 1)),
            (
                0x20,
                0,
                list_len,
                run(list_at, list_len.div_ceil(CLUSTER), 1),
            ),
        ],
    );
    for k in 0..records {
        let size = if k == 0 { 16 * CLUSTER } else { 0 };
        record(
            FIRST + k,
            &[(0x80, (k * runs_each) as u64, size, run(10, 1, runs_each))],
        );
    }
    vol
}

/// Each extent can hold as many runs as a record has room for, and a file can
/// have thousands of extents: the runs of one file are bounded in all, and the
/// file past the bound is reported, not read from the part of it that was kept.
#[test]
fn the_runs_of_all_the_extents_of_a_file_are_bounded() {
    let start = std::time::Instant::now();
    let e = members(&volume_with_extents(4000, 280));
    let file = e
        .iter()
        .find(|x| x.name == "<mft-record-16>")
        .unwrap_or_else(|| {
            panic!(
                "{:?}",
                e.iter()
                    .map(|x| (&x.name, x.unsupported))
                    .collect::<Vec<_>>()
            )
        });
    assert!(
        file.unsupported.is_some_and(|r| r.contains("more extents")),
        "{:?}",
        file.unsupported
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

/// The same shape within the bound is read.
#[test]
fn a_file_of_a_few_extents_with_many_runs_is_read() {
    let e = members(&volume_with_extents(40, 280));
    assert!(
        e.iter()
            .any(|x| x.name == "<mft-record-16>" && x.unsupported.is_none()),
        "{:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
