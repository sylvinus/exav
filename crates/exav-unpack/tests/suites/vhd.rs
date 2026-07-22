//! VHD disk images — fixed and dynamic reconstruction, and the cases exav
//! cannot assemble.
//!
//! Windows mounts a `.vhd` by double-click, so a payload inside one reaches the
//! user with no third-party tool. Anything exav cannot reconstruct must be
//! reported, not passed over.

use exav_unpack::{extract_each, Budget, Entry, Format, Limits};

const SECTOR: usize = 512;
const FOOTER: usize = 512;

/// A VHD footer. All fields big-endian; only the ones exav reads are filled in.
fn footer(disk_type: u32, data_offset: u64, current_size: u64) -> Vec<u8> {
    let mut f = vec![0u8; FOOTER];
    f[0..8].copy_from_slice(b"conectix");
    f[16..24].copy_from_slice(&data_offset.to_be_bytes());
    f[48..56].copy_from_slice(&current_size.to_be_bytes());
    f[60..64].copy_from_slice(&disk_type.to_be_bytes());
    f
}

/// A dynamic-disk header. `bat_off` and the geometry are what exav walks.
fn dyn_header(bat_off: u64, max_entries: u32, block_size: u32) -> Vec<u8> {
    let mut h = vec![0u8; 1024];
    h[0..8].copy_from_slice(b"cxsparse");
    h[16..24].copy_from_slice(&bat_off.to_be_bytes());
    h[28..32].copy_from_slice(&max_entries.to_be_bytes());
    h[32..36].copy_from_slice(&block_size.to_be_bytes());
    h
}

fn emitted(blob: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut b = Budget::new(Limits::default());
    let _ = extract_each(
        Format::Vhd,
        blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

const PAYLOAD: &[u8] = b"PAYLOAD-INSIDE-THE-DISK";

#[test]
fn a_fixed_vhd_is_detected_and_its_disk_extracted() {
    let mut disk = vec![0u8; SECTOR * 4];
    disk[100..100 + PAYLOAD.len()].copy_from_slice(PAYLOAD);
    let mut blob = disk.clone();
    blob.extend_from_slice(&footer(2, u64::MAX, disk.len() as u64));

    assert_eq!(exav_unpack::detect(&blob), Some(Format::Vhd));
    let e = emitted(&blob);
    assert!(
        e.iter()
            .any(|x| x.unsupported.is_none()
                && x.data.windows(PAYLOAD.len()).any(|w| w == PAYLOAD)),
        "the payload inside a fixed VHD must be reachable, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported, x.data.len()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_dynamic_vhd_is_reassembled_from_its_block_table() {
    // Two blocks; only the second is allocated, so the first must read as
    // zeroes exactly as it does when Windows mounts the image.
    let block_size: u32 = 2 * SECTOR as u32;
    let bitmap = SECTOR; // one sector of bitmap ahead of each block

    let mut blob = footer(3, FOOTER as u64, (block_size as u64) * 2);
    blob.extend_from_slice(&dyn_header((FOOTER + 1024) as u64, 2, block_size));
    // BAT: entry 0 unallocated, entry 1 at the sector after the BAT.
    let bat_off = FOOTER + 1024;
    let data_sector = ((bat_off + 8).div_ceil(SECTOR)) as u32;
    blob.extend_from_slice(&u32::MAX.to_be_bytes());
    blob.extend_from_slice(&data_sector.to_be_bytes());
    blob.resize(data_sector as usize * SECTOR, 0);
    blob.extend_from_slice(&vec![0u8; bitmap]); // sector bitmap
    let mut block = vec![0u8; block_size as usize];
    block[10..10 + PAYLOAD.len()].copy_from_slice(PAYLOAD);
    blob.extend_from_slice(&block);
    blob.extend_from_slice(&footer(3, FOOTER as u64, (block_size as u64) * 2));

    let e = emitted(&blob);
    let disk = e
        .iter()
        .find(|x| x.unsupported.is_none())
        .unwrap_or_else(|| panic!("no reassembled disk, got {e:?}"));
    assert!(
        disk.data.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
        "the payload in the allocated block must be reachable"
    );
    assert!(
        disk.data[..block_size as usize].iter().all(|&b| b == 0),
        "an unallocated block must read as zeroes"
    );
}

#[test]
fn a_differencing_vhd_is_reported_not_passed_over() {
    // Its payload lives in a parent image that is not in this file, so the disk
    // cannot be assembled — but saying nothing would report clean on a container
    // whose contents were never seen.
    let mut blob = vec![0u8; SECTOR * 2];
    blob.extend_from_slice(&footer(4, FOOTER as u64, 1024 * 1024));
    let e = emitted(&blob);
    assert!(
        e.iter()
            .any(|x| x.unsupported.is_some_and(|r| r.contains("differencing"))),
        "a differencing VHD must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_dynamic_vhd_with_an_unreadable_block_table_is_reported() {
    // The header points the BAT outside the image: exav cannot assemble the disk
    // at all, which is different from assembling a partly-zero one.
    let mut blob = footer(3, FOOTER as u64, 4096);
    blob.extend_from_slice(&dyn_header(0xFFFF_FFFF, 2, 2 * SECTOR as u32));
    blob.extend_from_slice(&footer(3, FOOTER as u64, 4096));
    let e = emitted(&blob);
    assert!(
        e.iter().any(|x| x.unsupported.is_some()),
        "an unreadable BAT must be reported, got {:?}",
        e.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_dynamic_vhd_declaring_an_enormous_disk_is_bounded_not_allocated() {
    // A small file can declare a huge virtual disk — a decompression bomb by
    // another name. It must be refused by the budget and reported, never
    // allocated.
    let mut blob = footer(3, FOOTER as u64, u64::MAX / 2);
    blob.extend_from_slice(&dyn_header(
        (FOOTER + 1024) as u64,
        1_000_000,
        2 * SECTOR as u32,
    ));
    blob.extend_from_slice(&vec![0xFFu8; 4_000_000]); // BAT, all unallocated
    blob.extend_from_slice(&footer(3, FOOTER as u64, u64::MAX / 2));

    let mut b = Budget::new(Limits {
        max_buffer_bytes: 1024 * 1024,
        ..Limits::default()
    });
    let mut out = Vec::new();
    let _ = extract_each(
        Format::Vhd,
        &blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    assert!(
        out.iter().all(|x| x.data.len() <= 1024 * 1024),
        "must not allocate past the budget"
    );
    assert!(
        out.iter().any(|x| x.unsupported.is_some()),
        "an over-budget disk must be reported, got {:?}",
        out.iter()
            .map(|x| (&x.name, x.unsupported))
            .collect::<Vec<_>>()
    );
}
