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
//! visible to a raw scan wherever they happen to land. Reading the disk still
//! matters: blocks are placed in arbitrary file order and sparse ranges are
//! absent entirely, so a payload spanning a block boundary appears in the file
//! only as two disjoint fragments — and a filesystem inside cannot be walked at
//! all until the guest disk is put back in order.
//!
//! The disk is a [`VDisk`]: one member when it fits the buffer limit, else its
//! filesystems are walked in place (see `vdisk.rs`). The block allocation table
//! is read from the source as blocks are reached.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use super::vdisk::{self, bytes_at, le32, le64, Health, Layout, Map, VDisk};
use super::volumes::report;
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, LimitHit};

/// The two region tables, at 192 KiB and 256 KiB. The second is a mirror, read
/// when the first does not parse.
const REGION_TABLE_1: u64 = 192 * 1024;
const REGION_TABLE_2: u64 = 256 * 1024;
const REGION_SIGNATURE: &[u8; 4] = b"regi";
const METADATA_SIGNATURE: &[u8; 8] = b"metadata";

/// A region table holds at most 2047 entries per the specification.
const MAX_REGION_ENTRIES: u32 = 2047;
/// Likewise for metadata items — the table is one 64 KiB region.
const MAX_METADATA_ENTRIES: u16 = 2047;
/// Both tables are one 64 KiB region.
const TABLE_LEN: usize = 64 * 1024;

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

const NAME: &str = "vhdx-disk";

fn le_u16(d: &[u8], off: usize) -> u16 {
    crate::bytes::at(d, off, 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    crate::bytes::at(d, off, 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn le_u64(d: &[u8], off: usize) -> u64 {
    crate::bytes::at(d, off, 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

/// Where a region lives in the file, and how long it is.
struct Region {
    offset: u64,
    length: u64,
}

/// Find the BAT and metadata regions in whichever region table parses.
fn regions(src: &dyn ByteSource) -> Option<(Region, Region)> {
    for base in [REGION_TABLE_1, REGION_TABLE_2] {
        let Some(t) = bytes_at(src, base, 16) else {
            continue;
        };
        if t[..4] != REGION_SIGNATURE[..] {
            continue;
        }
        let count = le32(src, base.saturating_add(8))
            .unwrap_or(0)
            .min(MAX_REGION_ENTRIES);
        let (mut bat, mut meta) = (None, None);
        for i in 0..u64::from(count) {
            let e = base.saturating_add(16).saturating_add(i.saturating_mul(32));
            // Entry: GUID(16), FileOffset u64, Length u32, Required u32.
            let Some(entry) = bytes_at(src, e, 28) else {
                break;
            };
            let r = Region {
                offset: le_u64(&entry, 16),
                length: u64::from(le_u32(&entry, 24)),
            };
            if entry[..16] == BAT_REGION {
                bat = Some(r);
            } else if entry[..16] == METADATA_REGION {
                meta = Some(r);
            }
        }
        if let (Some(bat), Some(meta)) = (bat, meta) {
            return Some((bat, meta));
        }
    }
    None
}

/// The three metadata items reading the disk needs.
struct Geometry {
    block_size: u32,
    virtual_size: u64,
    logical_sector_size: u32,
    has_parent: bool,
}

fn geometry(src: &dyn ByteSource, meta: &Region) -> Option<Geometry> {
    let base = meta.offset;
    let table = bytes_at(src, base, TABLE_LEN).or_else(|| {
        // A table cut short by the end of the file still has its entries.
        let n = (src.len() as u64).saturating_sub(base);
        bytes_at(src, base, usize::try_from(n).ok()?.min(TABLE_LEN))
    })?;
    if table.get(..8) != Some(METADATA_SIGNATURE.as_slice()) {
        return None;
    }
    let count = le_u16(&table, 10).min(MAX_METADATA_ENTRIES);
    let mut g = Geometry {
        block_size: 0,
        virtual_size: 0,
        // Every VHDX in the wild uses 512; the item is only absent in malformed
        // files, where this keeps the chunk-ratio arithmetic meaningful.
        logical_sector_size: 512,
        has_parent: false,
    };
    for i in 0..usize::from(count) {
        let e = i.saturating_mul(32).saturating_add(32);
        let Some(guid) = crate::bytes::at(&table, e, 16) else {
            break;
        };
        // Item offsets are relative to the start of the metadata region.
        let item = base.saturating_add(u64::from(le_u32(&table, e.saturating_add(16))));
        if guid == FILE_PARAMETERS {
            g.block_size = le32(src, item).unwrap_or(0);
            g.has_parent = le32(src, item.saturating_add(4)).unwrap_or(0) & HAS_PARENT != 0;
        } else if guid == VIRTUAL_DISK_SIZE {
            g.virtual_size = le64(src, item).unwrap_or(0);
        } else if guid == LOGICAL_SECTOR_SIZE {
            let s = le32(src, item).unwrap_or(0);
            if s != 0 {
                g.logical_sector_size = s;
            }
        }
    }
    (g.block_size != 0 && g.virtual_size != 0).then_some(g)
}

/// A VHDX disk: blocks placed by the Block Allocation Table.
struct Vhdx<'a> {
    src: &'a dyn ByteSource,
    bat: Region,
    block: u64,
    size: u64,
    /// Payload entries between the sector-bitmap entries the BAT interleaves.
    chunk_ratio: u64,
    file_len: u64,
    /// Blocks past the end of the table the region declares.
    unlocatable: u64,
}

impl Vhdx<'_> {
    /// The BAT index of block `idx`: one sector-bitmap entry follows every
    /// `chunk_ratio` payload entries, so it is not the block's index on the
    /// disk.
    fn bat_index(&self, idx: u64) -> u64 {
        idx.saturating_add(idx.checked_div(self.chunk_ratio).unwrap_or(0))
    }

    /// Whether the region declares an entry for block `idx`.
    fn has_entry(&self, idx: u64) -> bool {
        self.bat_index(idx).saturating_mul(8).saturating_add(8) <= self.bat.length
    }

    /// How many blocks, from the first, the table has an entry for.
    fn covered(&self, blocks: u64) -> u64 {
        // The entries needed grow with the index, so the blocks without one
        // are a suffix.
        let (mut lo, mut hi) = (0u64, blocks);
        while lo < hi {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            if self.has_entry(mid) {
                lo = mid.saturating_add(1);
            } else {
                hi = mid;
            }
        }
        lo
    }
}

impl Layout for Vhdx<'_> {
    fn name(&self) -> &'static str {
        NAME
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn unit(&self) -> u64 {
        self.block
    }

    fn map(&self, idx: u64) -> Map {
        // Past the end of the declared BAT region the table is short, so this
        // block and every one after it has no entry to read.
        if !self.has_entry(idx) {
            return Map::Zero;
        }
        let at = self
            .bat
            .offset
            .saturating_add(self.bat_index(idx).saturating_mul(8));
        let Some(entry) = le64(self.src, at) else {
            return Map::Zero;
        };
        let state = entry & 7;
        if state != PAYLOAD_BLOCK_FULLY_PRESENT && state != PAYLOAD_BLOCK_PARTIALLY_PRESENT {
            return Map::Zero; // unallocated or explicitly zero
        }
        // Bits 20..63 hold the file offset in megabytes.
        let host = (entry >> 20) << 20;
        let n = self
            .block
            .min(self.size.saturating_sub(idx.saturating_mul(self.block)));
        // An entry pointing past the end of the file names bytes that are
        // absent rather than hidden, so the block stays zero and stays quiet.
        host.checked_add(n)
            .is_some_and(|end| end <= self.file_len)
            .then_some(host)
            .map_or(Map::Zero, Map::Plain)
    }

    fn reports(&self, _health: &Health) -> Vec<(u64, &'static str)> {
        if self.unlocatable == 0 {
            return Vec::new();
        }
        // Reported alongside the disk, not instead of it: what was read
        // is still worth scanning, and the hole is still worth knowing about.
        vec![(
            self.unlocatable.saturating_mul(self.block),
            "VHDX block allocation table is shorter than the disk it describes",
        )]
    }
}

/// Walk a VHDX's disk.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let file_len = src.len() as u64;
    if file_len <= REGION_TABLE_1 || bytes_at(src, 0, 8).as_deref() != Some(b"vhdxfile".as_slice())
    {
        return Ok(None);
    }
    let Some((bat, meta)) = regions(src) else {
        return report(
            NAME,
            0,
            "VHDX region table names no BAT or metadata region",
            budget,
            visit,
        );
    };
    let Some(g) = geometry(src, &meta) else {
        return report(
            NAME,
            0,
            "VHDX metadata does not give the disk geometry",
            budget,
            visit,
        );
    };
    if g.has_parent {
        // The blocks this image lacks live in the parent, which is a separate
        // file — the same shape as a differencing VHD.
        return report(
            NAME,
            g.virtual_size,
            "differencing VHDX: the disk is a delta against a parent image not in this file",
            budget,
            visit,
        );
    }
    // The block size is a power of two between 1 MiB and 256 MiB; outside that
    // the chunk-ratio arithmetic below is meaningless.
    if !g.block_size.is_power_of_two() || !(1 << 20..=1 << 28).contains(&g.block_size) {
        return report(
            NAME,
            g.virtual_size,
            "implausible VHDX block size",
            budget,
            visit,
        );
    }
    let chunk_ratio = (1u64 << 23)
        .saturating_mul(u64::from(g.logical_sector_size))
        .checked_div(u64::from(g.block_size))
        .unwrap_or(0);
    let block = u64::from(g.block_size);
    let total_blocks = g.virtual_size.div_ceil(block);
    let mut layout = Vhdx {
        src,
        bat,
        block,
        size: g.virtual_size,
        chunk_ratio,
        file_len,
        unlocatable: 0,
    };
    layout.unlocatable = total_blocks.saturating_sub(layout.covered(total_blocks));
    let allowance = budget.remaining_scan();
    vdisk::walk(VDisk::new(src, layout, allowance), budget, visit)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn layout<'a>(src: &'a dyn ByteSource, bat_len: u64, ratio: u64) -> Vhdx<'a> {
        Vhdx {
            src,
            bat: Region {
                offset: 0,
                length: bat_len,
            },
            block: 1 << 20,
            size: 1 << 40,
            chunk_ratio: ratio,
            file_len: 0,
            unlocatable: 0,
        }
    }

    /// The blocks the table has an entry for are found by search; they are the
    /// ones a walk over every block would count, whatever the table's length
    /// and however the sector-bitmap entries are interleaved.
    #[test]
    fn the_blocks_a_short_table_covers_are_those_with_an_entry() {
        let src: &[u8] = &[];
        for ratio in [0u64, 1, 4, 16] {
            for entries in 0..40u64 {
                let l = layout(&src, entries * 8, ratio);
                for blocks in [0u64, 1, 7, 33, 100] {
                    let brute = (0..blocks).take_while(|&i| l.has_entry(i)).count() as u64;
                    assert_eq!(l.covered(blocks), brute, "{ratio} {entries} {blocks}");
                }
            }
        }
        // An entry is eight bytes: a length that cuts one does not hold it.
        let l = layout(&src, 8 * 3 + 7, 0);
        assert_eq!(l.covered(10), 3);
    }

    /// With a sector-bitmap entry after every four payload entries, block 4
    /// is at index 5.
    #[test]
    fn a_block_is_found_past_the_sector_bitmap_entries() {
        let src: &[u8] = &[];
        let l = layout(&src, 1 << 20, 4);
        assert_eq!(
            (0..8).map(|i| l.bat_index(i)).collect::<Vec<_>>(),
            [0, 1, 2, 3, 5, 6, 7, 8]
        );
    }
}
