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
//! Two of the three disk types are read:
//!
//! * **Fixed** (`disk_type == 2`) — the file *is* the raw disk, followed by a
//!   512-byte footer.
//! * **Dynamic** (`disk_type == 3`) — a Block Allocation Table maps each block
//!   of the virtual disk to a location in the file, or marks it unallocated.
//!   Unallocated blocks read as zeroes, exactly as they do when Windows mounts
//!   the image. The table is read from the source as blocks are reached, never
//!   held.
//!
//! **Differencing** (`disk_type == 4`) images are *not* read: they hold
//! only the delta against a parent `.vhd` that is not in this file, so the disk
//! cannot be assembled from what we have. That is reported, never passed over —
//! see [`walk`].
//!
//! The disk is a [`VDisk`]: one member when it fits the buffer limit, else its
//! filesystems are walked in place (see `vdisk.rs`).

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use super::vdisk::{self, Layout, Map, VDisk, be32, bytes_at};
use super::volumes::report;
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, LimitHit};

const FOOTER_LEN: u64 = 512;
const FOOTER_COOKIE: &[u8; 8] = b"conectix";
const DYN_COOKIE: &[u8; 8] = b"cxsparse";
const SECTOR: u64 = 512;

/// Sentinel BAT entry meaning "this block has never been written".
const BAT_UNUSED: u32 = 0xFFFF_FFFF;

const DISK_TYPE_FIXED: u32 = 2;
const DISK_TYPE_DYNAMIC: u32 = 3;
const DISK_TYPE_DIFFERENCING: u32 = 4;

const NAME: &str = "vhd-disk";

fn be_u32(d: &[u8], off: usize) -> u32 {
    crate::bytes::at(d, off, 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn be_u64(d: &[u8], off: usize) -> u64 {
    crate::bytes::at(d, off, 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

/// Locate the authoritative footer: the trailing copy, falling back to the
/// leading one that dynamic and differencing images also keep at offset 0.
fn footer(src: &dyn ByteSource) -> Option<Vec<u8>> {
    let len = src.len() as u64;
    if let Some(tail) = len
        .checked_sub(FOOTER_LEN)
        .and_then(|at| bytes_at(src, at, FOOTER_LEN as usize))
        && tail.starts_with(FOOTER_COOKIE)
    {
        return Some(tail.into_owned());
    }
    let head = bytes_at(src, 0, FOOTER_LEN as usize)?;
    head.starts_with(FOOTER_COOKIE).then(|| head.into_owned())
}

/// A fixed disk: the file up to its footer.
struct Flat {
    size: u64,
}

impl Layout for Flat {
    fn name(&self) -> &'static str {
        NAME
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn unit(&self) -> u64 {
        1 << 20
    }

    fn map(&self, idx: u64) -> Map {
        Map::Plain(idx.saturating_mul(self.unit()))
    }
}

/// A dynamic disk: blocks placed by the Block Allocation Table.
struct Dynamic<'a> {
    src: &'a dyn ByteSource,
    bat: u64,
    /// The virtual disk's size: the footer's, if the table covers it.
    size: u64,
    block: u64,
    /// The sector bitmap ahead of each block, padded to a sector.
    bitmap: u64,
    file_len: u64,
}

impl Dynamic<'_> {
    /// Where block `idx`, whose table entry is `ent`, is in the file, when
    /// all of it is there.
    fn place(&self, ent: u32, idx: u64) -> Option<u64> {
        let host = u64::from(ent)
            .saturating_mul(SECTOR)
            .saturating_add(self.bitmap);
        let n = self
            .block
            .min(self.size.saturating_sub(idx.saturating_mul(self.block)));
        host.checked_add(n)
            .is_some_and(|end| end <= self.file_len)
            .then_some(host)
    }

    /// Whether the table allocates blocks and every one of them is outside
    /// the file: not a truncated image but one that was not read at all.
    fn all_outside(&self) -> bool {
        const STEP: u64 = 16 * 1024;
        let blocks = self.size.div_ceil(self.block);
        let (mut allocated, mut missing) = (0u64, 0u64);
        let mut i = 0u64;
        while i < blocks {
            let n = blocks.saturating_sub(i).min(STEP);
            let at = self.bat.saturating_add(i.saturating_mul(4));
            let Some(chunk) = bytes_at(
                self.src,
                at,
                usize::try_from(n).unwrap_or(0).saturating_mul(4),
            ) else {
                break;
            };
            for (k, e) in chunk.as_chunks::<4>().0.iter().enumerate() {
                let ent = u32::from_be_bytes(*e);
                if ent == BAT_UNUSED {
                    continue;
                }
                allocated = allocated.saturating_add(1);
                let idx = i.saturating_add(k as u64);
                if self.place(ent, idx).is_none() {
                    missing = missing.saturating_add(1);
                }
            }
            i = i.saturating_add(n);
        }
        allocated > 0 && missing == allocated
    }
}

impl Layout for Dynamic<'_> {
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
        let Some(ent) = be32(self.src, self.bat.saturating_add(idx.saturating_mul(4))) else {
            return Map::Zero;
        };
        if ent == BAT_UNUSED {
            return Map::Zero; // never written: reads as zeroes when mounted, as here
        }
        // A BAT that points at a block outside the file is a truncated image:
        // those bytes are absent rather than hidden, so they stay zero.
        self.place(ent, idx).map_or(Map::Zero, Map::Plain)
    }
}

/// Walk a VHD's disk.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let Some(f) = footer(src) else {
        return Ok(None);
    };
    // Footer layout: +16 data offset (u64), +48 current size (u64),
    // +60 disk type (u32).
    let disk_type = be_u32(&f, 60);
    let current_size = be_u64(&f, 48);
    let allowance = budget.remaining_scan();

    match disk_type {
        DISK_TYPE_FIXED => {
            // The disk is everything before the trailing footer.
            let size = (src.len() as u64).saturating_sub(FOOTER_LEN);
            if size == 0 {
                return Ok(None);
            }
            vdisk::walk(VDisk::new(src, Flat { size }, allowance), budget, visit)
        }
        DISK_TYPE_DYNAMIC => dynamic(src, &f, current_size, budget, visit),
        DISK_TYPE_DIFFERENCING => {
            // The payload lives in a parent image this file does not contain, so
            // the disk cannot be assembled here at all. That is content
            // present-elsewhere-but-unreadable, not content absent: say so.
            report(
                NAME,
                current_size,
                "differencing VHD: the disk is a delta against a parent image not in this file",
                budget,
                visit,
            )
        }
        other => report(
            NAME,
            current_size,
            match other {
                0 | 1 => "VHD marked as no-disk/reserved",
                _ => "unsupported VHD disk type",
            },
            budget,
            visit,
        ),
    }
}

/// Read a dynamic VHD through its Block Allocation Table.
fn dynamic<T>(
    src: &dyn ByteSource,
    f: &[u8],
    current_size: u64,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let file_len = src.len() as u64;
    let Some(hdr) = bytes_at(src, be_u64(f, 16), 1024) else {
        return report(
            NAME,
            current_size,
            "dynamic VHD header lies outside the image",
            budget,
            visit,
        );
    };
    if !hdr.starts_with(DYN_COOKIE) {
        return report(
            NAME,
            current_size,
            "dynamic VHD header is missing or corrupt",
            budget,
            visit,
        );
    }
    // Dynamic header: +16 BAT offset (u64), +28 max table entries (u32),
    // +32 block size (u32).
    let bat = be_u64(&hdr, 16);
    let max_entries = u64::from(be_u32(&hdr, 28));
    let block = u64::from(be_u32(&hdr, 32));
    // A block size that is not a sane power-of-two multiple of the sector size
    // would make the sector bitmap length meaningless.
    if block == 0 || !block.is_multiple_of(SECTOR) || !block.is_power_of_two() || max_entries == 0 {
        return report(
            NAME,
            current_size,
            "dynamic VHD geometry is implausible",
            budget,
            visit,
        );
    }
    // Each block is preceded by a sector bitmap, padded up to a sector boundary.
    let bitmap = ((block / SECTOR).div_ceil(8)).next_multiple_of(SECTOR);
    // The table is read as blocks are reached, but it has to be in the file.
    if !bat
        .checked_add(max_entries.saturating_mul(4))
        .is_some_and(|end| end <= file_len)
    {
        return report(
            NAME,
            current_size,
            "dynamic VHD block allocation table lies outside the image",
            budget,
            visit,
        );
    }
    let layout = Dynamic {
        src,
        bat,
        size: current_size.min(max_entries.saturating_mul(block)),
        block,
        bitmap,
        file_len,
    };
    // A BAT whose every allocated entry points outside the file is not a
    // truncated image, it is one exav failed to read at all.
    if layout.all_outside() {
        return report(
            NAME,
            current_size,
            "dynamic VHD block table points entirely outside the image",
            budget,
            visit,
        );
    }
    let allowance = budget.remaining_scan();
    vdisk::walk(VDisk::new(src, layout, allowance), budget, visit)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Whether a table of `ents`, over a file of `file_len` bytes, in blocks of
    /// 1 KiB each preceded by a one-sector bitmap, is outside the file.
    fn outside(ents: &[u32], file_len: u64) -> bool {
        let bat: Vec<u8> = ents.iter().flat_map(|e| e.to_be_bytes()).collect();
        let src = bat.as_slice();
        let l = Dynamic {
            src: &src,
            bat: 0,
            size: ents.len() as u64 * 1024,
            block: 1024,
            bitmap: 512,
            file_len,
        };
        l.all_outside()
    }

    #[test]
    fn a_table_is_outside_the_file_only_if_every_allocated_block_is() {
        // Sector 100 is at byte 51200: a block there ends at 51200 + 512 + 1024.
        assert!(outside(&[100, 200], 40_000));
        assert!(!outside(&[100, 200], 60_000));
        // One block in, one out: a truncated image, not an unread one.
        assert!(!outside(&[10, 200], 8000));
        // Nothing allocated is not "everything outside".
        assert!(!outside(&[BAT_UNUSED, BAT_UNUSED], 100));
        // A block cut by the end of the file is not wholly in it.
        assert!(outside(&[100], 51_200 + 512 + 1023));
        assert!(!outside(&[100], 51_200 + 512 + 1024));
    }

    /// A table entry at the top of the range names a block that is not there,
    /// and the arithmetic placing it does not wrap.
    #[test]
    fn an_entry_at_the_top_of_the_range_is_outside() {
        assert!(outside(&[u32::MAX - 1], 1 << 40));
    }
}
