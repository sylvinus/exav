//! The logical partitions of an MBR disk: every one of them is walked.
//!
//! An extended partition holds a chain of boot records. A logical partition
//! starts where its own record says, relative to that record, and a record's
//! link to the next one is relative to the start of the extended partition.
//! Reading both relative to the record they are in puts the third logical
//! partition and the ones after it in the wrong place, and their filesystems
//! are not found.

use super::fs_tree::walked;
use exav_unpack::{Format, Limits};

const SECTOR: usize = 512;

/// A FAT12 volume of 128 sectors with one file in its root directory.
fn fat12(name: &[u8; 11], data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= SECTOR);
    let mut d = vec![0u8; 128 * SECTOR];
    d[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    d[3..11].copy_from_slice(b"MSDOS5.0");
    d[11..13].copy_from_slice(&512u16.to_le_bytes());
    // One sector to a cluster, one reserved sector, two FATs of one sector,
    // 16 root entries (one sector), 128 sectors, the data from sector 4.
    d[13] = 1;
    d[14..16].copy_from_slice(&1u16.to_le_bytes());
    d[16] = 2;
    d[17..19].copy_from_slice(&16u16.to_le_bytes());
    d[19..21].copy_from_slice(&128u16.to_le_bytes());
    d[21] = 0xF8;
    d[22..24].copy_from_slice(&1u16.to_le_bytes());
    d[38] = 0x29;
    d[54..62].copy_from_slice(b"FAT12   ");
    d[510..512].copy_from_slice(&[0x55, 0xAA]);
    for fat in [SECTOR, 2 * SECTOR] {
        d[fat..fat + 5].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF, 0x0F]);
    }
    let root = 3 * SECTOR;
    d[root..root + 11].copy_from_slice(name);
    d[root + 11] = 0x20;
    d[root + 26..root + 28].copy_from_slice(&2u16.to_le_bytes());
    d[root + 28..root + 32].copy_from_slice(&(data.len() as u32).to_le_bytes());
    d[4 * SECTOR..4 * SECTOR + data.len()].copy_from_slice(data);
    d
}

/// A table of up to four entries, (type, start, sectors), in sector `at`.
fn put_table(disk: &mut [u8], at: usize, entries: &[(u8, u32, u32)]) {
    for (i, (ptype, start, len)) in entries.iter().enumerate() {
        let e = at * SECTOR + 0x1BE + 16 * i;
        disk[e + 4] = *ptype;
        disk[e + 8..e + 12].copy_from_slice(&start.to_le_bytes());
        disk[e + 12..e + 16].copy_from_slice(&len.to_le_bytes());
    }
    disk[at * SECTOR + 510..at * SECTOR + 512].copy_from_slice(&[0x55, 0xAA]);
}

fn put(disk: &mut [u8], sector: usize, bytes: &[u8]) {
    disk[sector * SECTOR..sector * SECTOR + bytes.len()].copy_from_slice(bytes);
}

/// What the file of the volume of partition `k` holds.
fn marker(k: usize) -> Vec<u8> {
    format!("marker of the filesystem in partition {k}").into_bytes()
}

fn file_name(k: usize) -> [u8; 11] {
    let mut n = *b"MARK0   TXT";
    n[4] = b'0' + k as u8;
    n
}

/// A disk with a primary partition (sector 64) and an extended one (sector 256)
/// holding `logical` logical partitions, 300 sectors apart. Each volume holds
/// a file with a marker of its own.
fn disk(logical: usize) -> Vec<u8> {
    let mut disk = vec![0u8; (256 + 300 * logical + 300) * SECTOR];
    put_table(&mut disk, 0, &[(0x01, 64, 128), (0x0F, 256, 2048)]);
    put(&mut disk, 64, &fat12(&file_name(1), &marker(1)));
    for k in 0..logical {
        let record = 256 + 300 * k;
        // The partition is 8 sectors after its own record.
        let mut table = vec![(0x01, 8, 128)];
        if k + 1 < logical {
            // The link is relative to the extended partition.
            table.push((0x05, (300 * (k + 1)) as u32, 1));
        }
        put_table(&mut disk, record, &table);
        put(
            &mut disk,
            record + 8,
            &fat12(&file_name(k + 2), &marker(k + 2)),
        );
    }
    disk
}

/// The files of the volumes come out under the partitions' names, wherever the
/// chain of boot records puts them.
#[test]
fn the_filesystem_of_every_logical_partition_is_walked() {
    for logical in [1, 2, 4, 7] {
        let disk = disk(logical);
        // Volumes of 64 KiB are over this limit, so they are walked in place.
        let mut limits = Limits::default();
        limits.max_buffer_bytes = 32 * 1024;
        let (e, end) = walked(Format::Partition, &disk, limits);
        end.unwrap();
        let bad: Vec<_> = e
            .iter()
            .filter(|m| m.unsupported.is_some())
            .map(|m| (&m.name, m.unsupported))
            .collect();
        assert!(bad.is_empty(), "{logical} logical: {bad:?}");
        // The primary partition is number 1, the logical ones from 5.
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let mut want = vec![("mbr-part-1/MARK1.TXT".to_string(), text(&marker(1)))];
        for k in 0..logical {
            want.push((
                format!("mbr-part-{}/MARK{}.TXT", 5 + k, k + 2),
                text(&marker(k + 2)),
            ));
        }
        let got: Vec<_> = e.iter().map(|m| (m.name.clone(), text(&m.data))).collect();
        assert_eq!(got, want, "{logical} logical partitions");
    }
}
