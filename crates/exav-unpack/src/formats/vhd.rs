//! Virtual Hard Disk (VHD / Microsoft "conectix") images.
//!
//! Windows mounts a `.vhd` by double-click with no third-party tool, which makes
//! it a first-class delivery container: the victim opens it, the filesystem
//! inside appears, and the payload is a normal file on a normal drive. 7-Zip
//! opens them too. A scanner that cannot read one is asymmetric with the target
//! in the attacker's favour.
//!
//! Implemented clean-room from Microsoft's published *Virtual Hard Disk Image
//! Format Specification* (the VHD footer / dynamic-disk header layout is public).
//! All multi-byte fields are **big-endian**.
//!
//! Two of the three disk types are reconstructed:
//!
//! * **Fixed** (`disk_type == 2`) — the file *is* the raw disk, followed by a
//!   512-byte footer. Extraction is a slice.
//! * **Dynamic** (`disk_type == 3`) — a Block Allocation Table maps each block
//!   of the virtual disk to a location in the file, or marks it unallocated.
//!   Reconstruct the disk by walking the BAT; unallocated blocks read as zeroes,
//!   exactly as they do when Windows mounts the image.
//!
//! **Differencing** (`disk_type == 4`) images are *not* reconstructed: they hold
//! only the delta against a parent `.vhd` that is not in this file, so the disk
//! cannot be assembled from what we have. That is reported, never passed over —
//! see [`extract_vhd`].
//!
//! The reconstructed disk is emitted as a single member, which the partition and
//! filesystem handlers then pick up in the normal way.

use crate::{Budget, Entry, LimitHit, Sink};

const FOOTER_LEN: usize = 512;
const FOOTER_COOKIE: &[u8; 8] = b"conectix";
const DYN_COOKIE: &[u8; 8] = b"cxsparse";
const SECTOR: usize = 512;

/// Sentinel BAT entry meaning "this block has never been written".
const BAT_UNUSED: u32 = 0xFFFF_FFFF;

const DISK_TYPE_FIXED: u32 = 2;
const DISK_TYPE_DYNAMIC: u32 = 3;
const DISK_TYPE_DIFFERENCING: u32 = 4;

fn be_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn be_u64(d: &[u8], off: usize) -> u64 {
    d.get(off..off + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

/// Locate the authoritative footer: the trailing copy, falling back to the
/// leading one that dynamic and differencing images also keep at offset 0.
fn footer(data: &[u8]) -> Option<&[u8]> {
    let tail = data.get(data.len().checked_sub(FOOTER_LEN)?..)?;
    if tail.starts_with(FOOTER_COOKIE) {
        return Some(tail);
    }
    let head = data.get(..FOOTER_LEN)?;
    head.starts_with(FOOTER_COOKIE).then_some(head)
}

pub(crate) fn extract_vhd<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let Some(f) = footer(data) else {
        return Ok(None);
    };
    // Footer layout: +16 data offset (u64), +48 current size (u64),
    // +60 disk type (u32).
    let disk_type = be_u32(f, 60);
    let current_size = be_u48_size(f);

    match disk_type {
        DISK_TYPE_FIXED => {
            // The disk is everything before the trailing footer.
            let end = data.len().saturating_sub(FOOTER_LEN);
            emit(data.get(..end).unwrap_or(&[]), "vhd-disk", budget, visit)
        }
        DISK_TYPE_DYNAMIC => extract_dynamic(data, f, current_size, budget, visit),
        DISK_TYPE_DIFFERENCING => {
            // The payload lives in a parent image this file does not contain, so
            // the disk cannot be assembled here at all. That is content
            // present-elsewhere-but-unreadable, not content absent: say so.
            budget.count_entry()?;
            Ok(visit(
                Entry::unsupported(
                    "vhd-disk".to_string(),
                    current_size,
                    false,
                    "differencing VHD: the disk is a delta against a parent image not in this file",
                ),
                budget,
            ))
        }
        other => {
            budget.count_entry()?;
            Ok(visit(
                Entry::unsupported(
                    "vhd-disk".to_string(),
                    current_size,
                    false,
                    match other {
                        0 | 1 => "VHD marked as no-disk/reserved",
                        _ => "unsupported VHD disk type",
                    },
                ),
                budget,
            ))
        }
    }
}

/// `current size` from the footer (+48), the virtual disk's byte length.
fn be_u48_size(f: &[u8]) -> u64 {
    be_u64(f, 48)
}

/// Reassemble a dynamic VHD from its Block Allocation Table.
fn extract_dynamic<R>(
    data: &[u8],
    f: &[u8],
    current_size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let dyn_off = be_u64(f, 16) as usize;
    let Some(hdr) = data.get(dyn_off..dyn_off + 1024) else {
        return unreadable(
            "dynamic VHD header lies outside the image",
            current_size,
            budget,
            visit,
        );
    };
    if !hdr.starts_with(DYN_COOKIE) {
        return unreadable(
            "dynamic VHD header is missing or corrupt",
            current_size,
            budget,
            visit,
        );
    }
    // Dynamic header: +16 BAT offset (u64), +28 max table entries (u32),
    // +32 block size (u32).
    let bat_off = be_u64(hdr, 16) as usize;
    let max_entries = be_u32(hdr, 28) as usize;
    let block_size = be_u32(hdr, 32) as usize;
    // A block size that is not a sane power-of-two multiple of the sector size
    // would make the sector bitmap length meaningless.
    if block_size == 0
        || !block_size.is_multiple_of(SECTOR)
        || !block_size.is_power_of_two()
        || max_entries == 0
    {
        return unreadable(
            "dynamic VHD geometry is implausible",
            current_size,
            budget,
            visit,
        );
    }
    // Each block is preceded by a sector bitmap, padded up to a sector boundary.
    let bitmap_len = ((block_size / SECTOR).div_ceil(8)).next_multiple_of(SECTOR);

    let Some(bat) = data.get(bat_off..bat_off + max_entries.saturating_mul(4)) else {
        return unreadable(
            "dynamic VHD block allocation table lies outside the image",
            current_size,
            budget,
            visit,
        );
    };

    // Reserve the whole reconstructed disk up front: a dynamic VHD can declare a
    // very large virtual size from a small file, which is a decompression bomb by
    // another name.
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let want = current_size.min((max_entries as u64).saturating_mul(block_size as u64));
    if want > cap {
        return Ok(visit(
            Entry::unsupported(
                "vhd-disk".to_string(),
                want,
                false,
                "dynamic VHD exceeds the per-member size budget",
            ),
            budget,
        ));
    }

    let mut disk = vec![0u8; want as usize];
    let mut missing = 0usize;
    for i in 0..max_entries {
        let ent = be_u32(bat, i * 4);
        if ent == BAT_UNUSED {
            continue; // never written: reads as zeroes when mounted, as here
        }
        let src = (ent as usize)
            .saturating_mul(SECTOR)
            .saturating_add(bitmap_len);
        let dst = i.saturating_mul(block_size);
        if dst >= disk.len() {
            break;
        }
        let n = block_size.min(disk.len() - dst);
        match data.get(src..src + n) {
            Some(block) => disk[dst..dst + n].copy_from_slice(block),
            // The BAT points at a block outside the file: the image is truncated,
            // so those bytes are absent rather than hidden (they stay zero).
            // Counted so a wholly bogus table can be told apart from a healthy
            // one below.
            None => missing += 1,
        }
    }
    // A BAT whose every allocated entry points outside the file is not a
    // truncated image, it is one exav failed to read at all.
    let allocated = (0..max_entries)
        .filter(|&i| be_u32(bat, i * 4) != BAT_UNUSED)
        .count();
    if allocated > 0 && missing == allocated {
        return Ok(visit(
            Entry::unsupported(
                "vhd-disk".to_string(),
                current_size,
                false,
                "dynamic VHD block table points entirely outside the image",
            ),
            budget,
        ));
    }
    budget.commit(disk.len() as u64);
    Ok(visit(Entry::new("vhd-disk".to_string(), disk), budget))
}

fn unreadable<R>(
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported("vhd-disk".to_string(), size, false, reason),
        budget,
    ))
}

fn emit<R>(
    slice: &[u8],
    name: &str,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if slice.is_empty() {
        return Ok(None);
    }
    budget.count_entry()?;
    let cap = budget.reserve()?;
    if slice.len() as u64 > cap {
        return Ok(visit(
            Entry::unsupported(
                name.to_string(),
                slice.len() as u64,
                false,
                "VHD disk exceeds the per-member size budget",
            ),
            budget,
        ));
    }
    budget.commit(slice.len() as u64);
    Ok(visit(Entry::new(name.to_string(), slice.to_vec()), budget))
}
