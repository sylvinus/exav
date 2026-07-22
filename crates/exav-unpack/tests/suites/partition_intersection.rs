//! Overlapping partition entries — ClamAV's three
//! `Heuristics.*PartitionIntersect*` alerts.
//!
//! Two partitions claiming the same sectors is not something an installer
//! produces. It is parser confusion one layer below the ZIP case: the image
//! shows one filesystem to whatever mounts it and another to whatever scans it.
//!
//! The alert names are ClamAV's exactly, **including the doubled `n` in
//! `MBRPartitionnIntersect`**. That is an upstream typo, and reproducing it is
//! deliberate — the name is the API, and a gateway filtering on it would not
//! match a corrected spelling.

use exav_unpack::partition_intersection_alert;

const SECTOR: usize = 512;

/// An MBR with `parts` entries, each `(first_lba, sectors)`.
fn mbr(parts: &[(u32, u32)], total_sectors: usize) -> Vec<u8> {
    let mut d = vec![0u8; total_sectors * SECTOR];
    for (i, (lba, secs)) in parts.iter().enumerate().take(4) {
        let e = 0x1BE + i * 16;
        d[e] = 0x00; // status
        d[e + 4] = 0x83; // type: Linux
        d[e + 8..e + 12].copy_from_slice(&lba.to_le_bytes());
        d[e + 12..e + 16].copy_from_slice(&secs.to_le_bytes());
    }
    d[510] = 0x55;
    d[511] = 0xAA;
    d
}

#[test]
fn a_well_formed_table_is_not_flagged() {
    // Three partitions laid end to end, which is what every real disk looks
    // like. Firing here would flag ordinary disk images.
    let img = mbr(&[(2048, 2048), (4096, 2048), (6144, 2048)], 9000);
    assert_eq!(partition_intersection_alert(&img), None);
}

#[test]
fn overlapping_entries_are_flagged_with_clamavs_name() {
    // The second partition starts inside the first.
    let img = mbr(&[(2048, 4096), (4096, 2048)], 9000);
    assert_eq!(
        partition_intersection_alert(&img),
        Some("Heuristics.MBRPartitionnIntersect"),
        "the doubled `n` is ClamAV's spelling and must be reproduced verbatim"
    );
}

#[test]
fn a_single_partition_cannot_intersect() {
    let img = mbr(&[(2048, 4096)], 9000);
    assert_eq!(partition_intersection_alert(&img), None);
}

#[test]
fn identical_entries_are_flagged() {
    // The degenerate case: two entries describing exactly the same extent.
    let img = mbr(&[(2048, 2048), (2048, 2048)], 9000);
    assert!(partition_intersection_alert(&img).is_some());
}

#[test]
fn non_partition_input_reports_nothing() {
    assert_eq!(partition_intersection_alert(b""), None);
    assert_eq!(partition_intersection_alert(&vec![0u8; 4096]), None);
    // A file that merely ends in the boot signature is not a partition table.
    let mut fake = vec![0u8; 1024];
    fake[510] = 0x55;
    fake[511] = 0xAA;
    assert_eq!(partition_intersection_alert(&fake), None);
}
