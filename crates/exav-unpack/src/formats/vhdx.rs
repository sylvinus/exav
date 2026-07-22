//! VHDX — the modern Windows virtual disk.
//!
//! Windows mounts a VHDX on double-click, with no third-party tool, which makes
//! it one of the more plausible delivery containers on that platform. It
//! replaces VHD's flat footer-and-BAT layout with a region table pointing at a
//! GUID-keyed metadata table and a block allocation table.
//!
//! Implemented from Microsoft's published `[MS-VHDX]` specification. All fields
//! are **little-endian**, and the GUIDs are stored in the mixed-endian form
//! Windows uses (first three components byte-swapped).
//!
//! Payload blocks are stored uncompressed, so unlike QCOW2 the bytes are
//! visible to a raw scan wherever they happen to land. Reconstruction still
//! matters: blocks are placed in arbitrary file order and sparse ranges are
//! absent entirely, so a payload spanning a block boundary appears in the file
//! only as two disjoint fragments — and a filesystem inside cannot be walked at
//! all until the guest disk is put back in order.
//!
//! The reconstructed disk is emitted as a single member for the partition and
//! filesystem handlers to pick up.

use crate::{Budget, Entry, LimitHit, Sink};

/// The two region tables, at 192 KiB and 256 KiB. The second is a mirror, read
/// when the first does not parse.
const REGION_TABLE_1: usize = 192 * 1024;
const REGION_TABLE_2: usize = 256 * 1024;
const REGION_SIGNATURE: &[u8; 4] = b"regi";
const METADATA_SIGNATURE: &[u8; 8] = b"metadata";

/// A region table holds at most 2047 entries per the specification.
const MAX_REGION_ENTRIES: u32 = 2047;
/// Likewise for metadata items — the table is one 64 KiB region.
const MAX_METADATA_ENTRIES: u16 = 2047;

/// Region GUIDs, in stored (mixed-endian) byte order.
const BAT_REGION: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const METADATA_REGION: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];

/// Metadata item GUIDs, same encoding.
const FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];

/// BAT entry states. Only `FULLY_PRESENT` and `PARTIALLY_PRESENT` name a block
/// whose bytes are in this file; the rest read as zeroes (or, for a differencing
/// disk, come from the parent).
const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

/// `FileParameters` flag bit 1: the disk is a delta against a parent image.
const HAS_PARENT: u32 = 1 << 1;

fn le_u16(d: &[u8], off: usize) -> u16 {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn le_u64(d: &[u8], off: usize) -> u64 {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

/// Where a region lives in the file, and how long it is.
struct Region {
    offset: usize,
    length: usize,
}

/// Find the BAT and metadata regions in whichever region table parses.
fn regions(data: &[u8]) -> Option<(Region, Region)> {
    for base in [REGION_TABLE_1, REGION_TABLE_2] {
        if data.get(base..base + 4) != Some(REGION_SIGNATURE.as_slice()) {
            continue;
        }
        let count = le_u32(data, base + 8).min(MAX_REGION_ENTRIES);
        let (mut bat, mut meta) = (None, None);
        for i in 0..count as usize {
            let e = base + 16 + i * 32;
            let Some(guid) = data.get(e..e + 16) else {
                break;
            };
            // Entry: GUID(16), FileOffset u64, Length u32, Required u32.
            let r = Region {
                offset: le_u64(data, e + 16) as usize,
                length: le_u32(data, e + 24) as usize,
            };
            if guid == BAT_REGION {
                bat = Some(r);
            } else if guid == METADATA_REGION {
                meta = Some(r);
            }
        }
        if let (Some(bat), Some(meta)) = (bat, meta) {
            return Some((bat, meta));
        }
    }
    None
}

/// The three metadata items reconstruction needs.
struct Geometry {
    block_size: u32,
    virtual_size: u64,
    logical_sector_size: u32,
    has_parent: bool,
}

fn geometry(data: &[u8], meta: &Region) -> Option<Geometry> {
    let base = meta.offset;
    if data.get(base..base + 8) != Some(METADATA_SIGNATURE.as_slice()) {
        return None;
    }
    let count = le_u16(data, base + 10).min(MAX_METADATA_ENTRIES);
    let mut g = Geometry {
        block_size: 0,
        virtual_size: 0,
        // Every VHDX in the wild uses 512; the item is only absent in malformed
        // files, where this keeps the chunk-ratio arithmetic meaningful.
        logical_sector_size: 512,
        has_parent: false,
    };
    for i in 0..count as usize {
        let e = base + 32 + i * 32;
        let Some(guid) = data.get(e..e + 16) else {
            break;
        };
        // Item offsets are relative to the start of the metadata region.
        let item = base + le_u32(data, e + 16) as usize;
        if guid == FILE_PARAMETERS {
            g.block_size = le_u32(data, item);
            g.has_parent = le_u32(data, item + 4) & HAS_PARENT != 0;
        } else if guid == VIRTUAL_DISK_SIZE {
            g.virtual_size = le_u64(data, item);
        } else if guid == LOGICAL_SECTOR_SIZE {
            let s = le_u32(data, item);
            if s != 0 {
                g.logical_sector_size = s;
            }
        }
    }
    (g.block_size != 0 && g.virtual_size != 0).then_some(g)
}

pub(crate) fn extract_vhdx<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !super::sniff::is(data, crate::Format::Vhdx) {
        return Ok(None);
    }
    let Some((bat, meta)) = regions(data) else {
        return report(
            "VHDX region table names no BAT or metadata region",
            0,
            budget,
            visit,
        );
    };
    let Some(g) = geometry(data, &meta) else {
        return report(
            "VHDX metadata does not give the disk geometry",
            0,
            budget,
            visit,
        );
    };
    if g.has_parent {
        // The blocks this image lacks live in the parent, which is a separate
        // file — the same shape as a differencing VHD.
        return report(
            "differencing VHDX: the disk is a delta against a parent image not in this file",
            g.virtual_size,
            budget,
            visit,
        );
    }
    // The block size is a power of two between 1 MiB and 256 MiB; outside that
    // the chunk-ratio arithmetic below is meaningless.
    if !g.block_size.is_power_of_two() || !(1 << 20..=1 << 28).contains(&g.block_size) {
        return report("implausible VHDX block size", g.virtual_size, budget, visit);
    }

    budget.count_entry()?;
    let cap = budget.reserve()?;
    if g.virtual_size > cap {
        return Ok(visit(
            Entry::unsupported(
                "vhdx-disk".to_string(),
                g.virtual_size,
                false,
                "VHDX disk exceeds the per-member size budget",
            ),
            budget,
        ));
    }

    // The BAT interleaves one sector-bitmap entry after every `chunk_ratio`
    // payload entries, so a block's index in the table is not its index on the
    // disk.
    let chunk_ratio = ((1u64 << 23) * g.logical_sector_size as u64) / g.block_size as u64;
    let block_size = g.block_size as usize;
    let total_blocks = g.virtual_size.div_ceil(g.block_size as u64);

    let mut disk = vec![0u8; g.virtual_size as usize];
    // Blocks the BAT says are here but that could not be located. Zero-filling
    // one and saying nothing would hand the scanner a clean-looking hole where
    // real content should be.
    let mut unlocatable_blocks = 0usize;

    for i in 0..total_blocks {
        let bat_index = i + i.checked_div(chunk_ratio).unwrap_or(0);
        // Past the end of the declared BAT region: the table is short, so this
        // block and every one after it has no entry to read.
        if (bat_index as usize + 1) * 8 > bat.length {
            unlocatable_blocks += (total_blocks - i) as usize;
            break;
        }
        let entry = le_u64(data, bat.offset + (bat_index as usize) * 8);
        let state = entry & 7;
        if state != PAYLOAD_BLOCK_FULLY_PRESENT && state != PAYLOAD_BLOCK_PARTIALLY_PRESENT {
            continue; // unallocated or explicitly zero
        }
        // Bits 20..63 hold the file offset in megabytes.
        let host = ((entry >> 20) * (1 << 20)) as usize;
        let guest = (i as usize).saturating_mul(block_size);
        if guest >= disk.len() {
            continue;
        }
        // An entry pointing past the end of the file names bytes that are
        // absent rather than hidden, so the block stays zero and stays quiet.
        let n = block_size.min(disk.len() - guest);
        if let Some(src) = data.get(host..host + n) {
            disk[guest..guest + n].copy_from_slice(src);
        }
    }

    if unlocatable_blocks > 0 {
        // Reported alongside the disk, not instead of it: what was reconstructed
        // is still worth scanning, and the hole is still worth knowing about.
        budget.count_entry()?;
        if let Some(r) = visit(
            Entry::unsupported(
                "vhdx-disk".to_string(),
                (unlocatable_blocks as u64).saturating_mul(g.block_size as u64),
                false,
                "VHDX block allocation table is shorter than the disk it describes",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }
    budget.commit(disk.len() as u64);
    Ok(visit(Entry::new("vhdx-disk".to_string(), disk), budget))
}

fn report<R>(
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported("vhdx-disk".to_string(), size, false, reason),
        budget,
    ))
}
