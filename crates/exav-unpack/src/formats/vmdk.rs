//! VMDK — VMware's virtual disk.
//!
//! Two shapes matter here. A **sparse** VMDK maps the guest disk through a grain
//! directory and grain tables, much like QCOW2's two-level lookup. A
//! **streamOptimized** VMDK additionally deflate-compresses each grain and is
//! the format inside an OVA/OVF appliance — the usual way a VM image is
//! distributed, and therefore a plausible delivery container whose payload
//! appears nowhere in the file's bytes.
//!
//! Implemented from VMware's published Virtual Disk Format specification. Sparse
//! header fields are **little-endian**.
//!
//! A sparse extent's tables are read from the source as grains are reached,
//! never held. A streamOptimized extent is a stream of marker sectors, each
//! grain preceded by its guest LBA and compressed length: one pass over the
//! markers indexes where each grain is (the index, one entry per grain, is
//! counted against the buffer limit), and a grain is inflated when a read
//! reaches it.
//!
//! The disk is a [`VDisk`]: one member when it fits the buffer limit, else its
//! filesystems are walked in place (see `vdisk.rs`).

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashMap;

use super::vdisk::{self, bytes_at, le32, Health, Layout, Map, Unpacked, VDisk, MAX_PACKED_UNIT};
use super::volumes::report;
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, LimitHit, Salvaged};

const SECTOR: u64 = 512;
const HEADER_LEN: usize = 512;

/// Marker sector kinds used by streamOptimized extents.
const MARKER_EOS: u32 = 0;
const MARKER_GT: u32 = 1;
const MARKER_GD: u32 = 2;
const MARKER_FOOTER: u32 = 3;

/// A grain table entry of 1 marks a grain that reads as zeroes.
const GTE_ZEROED: u32 = 1;

/// What one entry of the streamOptimized index costs, for counting it against
/// the buffer limit.
const INDEX_ENTRY_COST: u64 = 64;

const NAME: &str = "vmdk-disk";

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

/// A sparse extent: grain directory, grain tables, grains.
struct Sparse<'a> {
    src: &'a dyn ByteSource,
    /// Byte offset of the grain directory.
    gd: u64,
    /// Entries in a grain table.
    gtes: u64,
    grain: u64,
    size: u64,
    file_len: u64,
}

impl Layout for Sparse<'_> {
    fn name(&self) -> &'static str {
        NAME
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn unit(&self) -> u64 {
        self.grain
    }

    fn map(&self, idx: u64) -> Map {
        let i = idx.checked_div(self.gtes).unwrap_or(0);
        let j = idx.checked_rem(self.gtes).unwrap_or(0);
        let gde = le32(self.src, self.gd.saturating_add(i.saturating_mul(4))).unwrap_or(0);
        if gde == 0 {
            return Map::Zero; // no grain table: unallocated
        }
        let gt = u64::from(gde).saturating_mul(SECTOR);
        // A grain table past the end is a truncated image.
        if gt
            .checked_add(self.gtes.saturating_mul(4))
            .is_none_or(|end| end > self.file_len)
        {
            return Map::Zero;
        }
        let gte = le32(self.src, gt.saturating_add(j.saturating_mul(4))).unwrap_or(0);
        if gte == 0 || gte == GTE_ZEROED {
            return Map::Zero;
        }
        let host = u64::from(gte).saturating_mul(SECTOR);
        let n = self
            .grain
            .min(self.size.saturating_sub(idx.saturating_mul(self.grain)));
        host.checked_add(n)
            .is_some_and(|end| end <= self.file_len)
            .then_some(host)
            .map_or(Map::Zero, Map::Plain)
    }
}

/// Where a streamOptimized grain's marker data is.
#[derive(Clone, Copy)]
struct Grain {
    at: u64,
    stored: u64,
    /// The file ends inside it.
    cut: bool,
}

/// A streamOptimized extent: grains found by walking its markers.
struct Stream<'a> {
    src: &'a dyn ByteSource,
    grain: u64,
    size: u64,
    index: HashMap<u64, Grain>,
    /// Grains in the file that could not be indexed: off a grain boundary, or
    /// more than the index holds.
    unplaced: u64,
}

impl<'a> Stream<'a> {
    /// Walk the markers from where the grain data begins.
    ///
    /// Grain data begins after the header's declared `overhead` — the sectors
    /// taken by the embedded descriptor and the redundant grain tables.
    /// Starting at the end of the header instead lands in the middle of that
    /// metadata and finds no grains at all.
    fn new(
        src: &'a dyn ByteSource,
        overhead_sectors: u64,
        grain: u64,
        size: u64,
        max_entries: usize,
    ) -> Self {
        let mut s = Stream {
            src,
            grain,
            size,
            index: HashMap::new(),
            unplaced: 0,
        };
        let file_len = src.len() as u64;
        let mut pos = overhead_sectors
            .saturating_mul(SECTOR)
            .max(HEADER_LEN as u64);
        // `pos` saturates at the top after a marker that skips past the file.
        while pos.saturating_add(SECTOR) <= file_len {
            // Marker: u64 LBA, u32 size, u32 type (the last only when size == 0).
            let Some(m) = bytes_at(src, pos, 16) else {
                break;
            };
            let lba = le_u64(&m, 0);
            let len = le_u32(&m, 8);
            if len == 0 {
                match le_u32(&m, 12) {
                    MARKER_EOS => break,
                    // Metadata regions: `lba` counts the sectors that follow.
                    MARKER_GT | MARKER_GD | MARKER_FOOTER => {
                        pos = pos
                            .saturating_add(SECTOR)
                            .saturating_add(lba.saturating_mul(SECTOR));
                    }
                    _ => pos = pos.saturating_add(SECTOR),
                }
                continue;
            }
            // A data marker: 12 bytes of header then `len` bytes of deflate,
            // padded out to a sector boundary.
            let start = pos.saturating_add(12);
            let len = u64::from(len);
            // A grain cut by the end of the file: what is there is decoded, the
            // rest is absent.
            let cut = start.saturating_add(len) > file_len;
            let guest = lba.saturating_mul(SECTOR);
            if guest < size {
                let idx = guest.checked_div(grain).unwrap_or(0);
                let aligned = guest.checked_rem(grain) == Some(0);
                let known = s.index.contains_key(&idx);
                if !aligned || (!known && s.index.len() >= max_entries) {
                    s.unplaced = s.unplaced.saturating_add(1);
                } else {
                    let stored = len.min(file_len.saturating_sub(start));
                    // A later marker for a grain replaces an earlier one.
                    s.index.insert(
                        idx,
                        Grain {
                            at: start,
                            stored,
                            cut,
                        },
                    );
                }
            }
            if cut {
                break;
            }
            let consumed = len
                .saturating_add(12)
                .div_ceil(SECTOR)
                .saturating_mul(SECTOR);
            pos = pos.saturating_add(consumed);
        }
        s
    }
}

impl Layout for Stream<'_> {
    fn name(&self) -> &'static str {
        NAME
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn unit(&self) -> u64 {
        self.grain
    }

    fn map(&self, idx: u64) -> Map {
        self.index.get(&idx).map_or(Map::Zero, |g| Map::Packed {
            at: g.at,
            stored: g.stored,
            cut: g.cut,
        })
    }

    fn unpack(&self, _idx: u64, at: u64, stored: u64, cut: bool, out: usize) -> Unpacked {
        let raw = usize::try_from(stored)
            .ok()
            .and_then(|n| bytes_at(self.src, at, n));
        let Some(raw) = raw else {
            return Unpacked {
                data: Vec::new(),
                damaged: true,
            };
        };
        let s = match crate::inflate::zlib_reader(&raw[..]) {
            Ok(Some(z)) => crate::salvage(z, out as u64),
            // Cut inside the zlib header, or not a zlib stream.
            Err(_) => Salvaged {
                data: Vec::new(),
                over_cap: false,
                undecoded: false,
                cut_short: true,
            },
            Ok(None) => Salvaged {
                data: Vec::new(),
                over_cap: false,
                undecoded: true,
                cut_short: false,
            },
        };
        // The grain's bytes are in this file; exav just could not read them.
        // That is content left unexamined, not content absent.
        Unpacked {
            damaged: s.part_way(cut),
            data: s.data,
        }
    }

    fn reports(&self, health: &Health) -> Vec<(u64, &'static str)> {
        // Reported alongside the disk, not instead of it. A grain that fails
        // to inflate leaves zeroes behind, and zeroes that nobody mentions
        // read exactly like empty disk.
        let mut out = Vec::new();
        if health.undecodable() > 0 {
            out.push((
                health
                    .undecodable()
                    .saturating_mul(self.grain)
                    .min(self.size),
                "streamOptimized VMDK: grains that could not be decompressed",
            ));
        }
        if self.unplaced > 0 {
            out.push((
                self.unplaced.saturating_mul(self.grain),
                "streamOptimized VMDK: grains off a grain boundary or beyond the index",
            ));
        }
        out
    }

    fn unusable(&self, health: &Health, whole: bool) -> Option<&'static str> {
        let none = self.index.is_empty() || (whole && health.produced() == 0);
        (none && self.size > 0).then_some("streamOptimized VMDK: no grain could be decoded")
    }
}

/// What a VMDK header makes of an image.
enum Opened<'a> {
    /// Not a VMDK extent at all.
    No,
    Sparse(Sparse<'a>),
    Stream(Stream<'a>),
    /// A file whose disk is not read: the size it declares, and why.
    Unread(u64, &'static str),
}

/// Read the header of `src`. A streamOptimized extent's markers are indexed
/// into at most `max_grains` entries.
fn open(src: &dyn ByteSource, max_grains: usize) -> Opened<'_> {
    let head = src.window(0, HEADER_LEN);
    if head.starts_with(b"# Disk DescriptorFile") {
        // The extents named here are separate files, absent from this one.
        return Opened::Unread(
            src.len() as u64,
            "VMDK descriptor: the disk extents are separate files not in this one",
        );
    }
    if !(src.len() > HEADER_LEN && head.starts_with(b"KDMV")) {
        return Opened::No;
    }

    let flags = le_u32(&head, 8);
    let capacity_sectors = le_u64(&head, 12);
    let grain_sectors = le_u64(&head, 20);
    let gtes = match le_u32(&head, 44) {
        0 => 512,
        n => n,
    };
    let gd_offset = le_u64(&head, 56);
    let overhead_sectors = le_u64(&head, 64);
    let compress_algorithm = head
        .get(77..79)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    // Bit 16 of `flags` marks compressed grains; bit 17 marks the marker-based
    // (streamOptimized) layout.
    let compressed = flags & (1 << 16) != 0 || compress_algorithm == 1;
    let size = capacity_sectors.saturating_mul(SECTOR);

    if grain_sectors == 0 || !grain_sectors.is_power_of_two() {
        return Opened::Unread(size, "implausible VMDK grain size");
    }
    let grain = grain_sectors.saturating_mul(SECTOR);

    // streamOptimized extents are written as a stream of marker sectors rather
    // than a navigable grain directory: each grain is preceded by its guest LBA
    // and compressed length, and the metadata markers can be skipped.
    if compressed || gd_offset == u64::MAX {
        // A grain is inflated whole into the cache.
        if grain > MAX_PACKED_UNIT {
            return Opened::Unread(size, "implausible VMDK grain size");
        }
        let layout = Stream::new(src, overhead_sectors, grain, size, max_grains);
        if layout.index.is_empty() && size > 0 {
            return Opened::Unread(size, "streamOptimized VMDK: no grain could be decoded");
        }
        return Opened::Stream(layout);
    }

    // Plain sparse: grain directory -> grain tables -> grains.
    if !gtes.is_power_of_two() || gtes > 1 << 16 {
        return Opened::Unread(size, "implausible VMDK grain table size");
    }
    let gtes = u64::from(gtes);
    let gd = gd_offset.saturating_mul(SECTOR);
    let num_gde = capacity_sectors
        .div_ceil(grain_sectors.saturating_mul(gtes))
        .max(1);
    let file_len = src.len() as u64;
    if !gd
        .checked_add(num_gde.saturating_mul(4))
        .is_some_and(|end| end <= file_len)
    {
        return Opened::Unread(size, "VMDK grain directory lies outside the image");
    }
    Opened::Sparse(Sparse {
        src,
        gd,
        gtes,
        grain,
        size,
        file_len,
    })
}

/// Walk a VMDK's disk.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let max_grains =
        usize::try_from(budget.limits().max_buffer_bytes / INDEX_ENTRY_COST).unwrap_or(usize::MAX);
    let allowance = budget.remaining_scan();
    match open(src, max_grains) {
        Opened::No => Ok(None),
        Opened::Unread(size, why) => report(NAME, size, why, budget, visit),
        Opened::Sparse(l) => vdisk::walk(VDisk::new(src, l, allowance), budget, visit),
        Opened::Stream(l) => vdisk::walk(VDisk::new(src, l, allowance), budget, visit),
    }
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    /// A sparse extent of 512 sectors in grains of one sector: the header, the
    /// grain directory at sector 1, its one grain table at sectors 2 to 5, and
    /// grain data from sector 6. `gte` is the table entry of grain 0.
    fn sparse(gte: u32, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 7 * 512];
        f[..4].copy_from_slice(b"KDMV");
        f[12..20].copy_from_slice(&512u64.to_le_bytes());
        f[20..28].copy_from_slice(&1u64.to_le_bytes());
        f[44..48].copy_from_slice(&512u32.to_le_bytes());
        f[56..64].copy_from_slice(&1u64.to_le_bytes());
        f[512..516].copy_from_slice(&2u32.to_le_bytes());
        f[1024..1028].copy_from_slice(&gte.to_le_bytes());
        f[6 * 512..6 * 512 + data.len()].copy_from_slice(data);
        f
    }

    fn first(img: &[u8], n: usize) -> Vec<u8> {
        let src = &img;
        let Opened::Sparse(l) = open(src, usize::MAX) else {
            panic!("a sparse extent");
        };
        let mut d = VDisk::new(src, l, u64::MAX);
        let mut out = vec![0u8; n];
        d.read_exact(&mut out).unwrap();
        out
    }

    fn unread(img: &[u8]) -> &'static str {
        let src = img;
        match open(&src, usize::MAX) {
            Opened::Unread(_, why) => why,
            _ => panic!("the image should not open as a disk"),
        }
    }

    #[test]
    fn a_grain_is_read_from_its_table_entry() {
        assert_eq!(&first(&sparse(6, b"payload"), 7), b"payload");
    }

    /// An entry of 1 is a grain that reads as zeros; read as the sector it
    /// names, it would be the extent's own descriptor area.
    #[test]
    fn a_grain_table_entry_of_one_reads_zeros() {
        // Sector 1 is the grain directory, which does not start with zeros.
        assert_eq!(first(&sparse(1, b"payload"), 7), [0u8; 7]);
        assert_eq!(first(&sparse(0, b"payload"), 7), [0u8; 7]);
    }

    #[test]
    fn a_grain_or_table_outside_the_file_reads_as_zeros() {
        assert_eq!(first(&sparse(7, b"payload"), 7), [0u8; 7]);
        assert_eq!(first(&sparse(u32::MAX, b"payload"), 7), [0u8; 7]);
        let mut img = sparse(6, b"payload");
        img[512..516].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(first(&img, 7), [0u8; 7]);
    }

    #[test]
    fn what_the_header_says_that_cannot_be_followed_is_reported() {
        let mut img = sparse(6, b"x");
        img[20..28].copy_from_slice(&3u64.to_le_bytes());
        assert!(unread(&img).contains("grain size"));
        let mut img = sparse(6, b"x");
        img[20..28].copy_from_slice(&0u64.to_le_bytes());
        assert!(unread(&img).contains("grain size"));
        for gtes in [3u32, 1 << 20] {
            let mut img = sparse(6, b"x");
            img[44..48].copy_from_slice(&gtes.to_le_bytes());
            assert!(unread(&img).contains("grain table size"), "{gtes}");
        }
        // The directory at the top of the range: the sum must not wrap.
        for gd in [1000u64, u64::MAX - 1, 1 << 60] {
            let mut img = sparse(6, b"x");
            img[56..64].copy_from_slice(&gd.to_le_bytes());
            assert!(unread(&img).contains("grain directory"), "{gd}");
        }
        // Compressed grains are inflated whole into the cache: not a huge one.
        let mut img = sparse(6, b"x");
        img[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
        img[20..28].copy_from_slice(&(1u64 << 30).to_le_bytes());
        assert!(unread(&img).contains("grain size"));
        let descriptor = b"# Disk DescriptorFile\nversion=1\n".to_vec();
        assert!(unread(&descriptor).contains("descriptor"));
        let short: &[u8] = b"KDMV";
        assert!(matches!(open(&short, usize::MAX), Opened::No));
    }

    /// One data marker for a grain of one sector, deflate of `grain`, then the
    /// end-of-stream marker.
    fn stream(markers: &[(u64, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut f = vec![0u8; 512];
        f[..4].copy_from_slice(b"KDMV");
        f[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
        f[12..20].copy_from_slice(&512u64.to_le_bytes());
        f[20..28].copy_from_slice(&1u64.to_le_bytes());
        f[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
        f[64..72].copy_from_slice(&1u64.to_le_bytes());
        for (lba, grain) in markers {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
            z.write_all(grain).unwrap();
            let z = z.finish().unwrap();
            f.extend_from_slice(&lba.to_le_bytes());
            f.extend_from_slice(&(z.len() as u32).to_le_bytes());
            f.extend_from_slice(&z);
            f.resize(f.len().next_multiple_of(512), 0);
        }
        f.extend_from_slice(&[0u8; 512]);
        f
    }

    fn grains(img: &[u8], max: usize) -> Option<(Vec<u8>, u64)> {
        let src = &img;
        let Opened::Stream(l) = open(src, max) else {
            return None;
        };
        let unplaced = l.unplaced;
        let mut d = VDisk::new(src, l, u64::MAX);
        let mut out = vec![0u8; 4 * 512];
        d.seek(SeekFrom::Start(0)).unwrap();
        d.read_exact(&mut out).unwrap();
        Some((out, unplaced))
    }

    /// A marker for a grain already seen replaces it, as a later write does.
    #[test]
    fn a_later_marker_replaces_an_earlier_one_for_the_same_grain() {
        let (a, b) = ([b'a'; 512], [b'b'; 512]);
        let img = stream(&[(1, &a), (1, &b), (2, &a)]);
        let (d, unplaced) = grains(&img, usize::MAX).unwrap();
        assert_eq!(&d[..512], &[0u8; 512][..]);
        assert_eq!(&d[512..1024], &b[..]);
        assert_eq!(&d[1024..1536], &a[..]);
        assert_eq!(unplaced, 0);
    }

    /// The index is counted against a limit; a grain past it is counted as one
    /// that could not be placed, not dropped.
    #[test]
    fn grains_past_the_index_limit_are_counted_not_dropped() {
        let a = [b'a'; 512];
        let img = stream(&[(0, &a), (1, &a), (2, &a)]);
        let (d, unplaced) = grains(&img, 2).unwrap();
        assert_eq!(&d[..1024], &[b'a'; 1024][..]);
        assert_eq!(&d[1024..1536], &[0u8; 512][..]);
        assert_eq!(unplaced, 1);
    }

    /// A grain damaged part way gave what decoded before the damage, and that
    /// is handed over with the report; a disk is not "no grain decoded" for
    /// having one bad grain.
    #[test]
    fn a_grain_damaged_part_way_keeps_its_prefix_and_is_reported() {
        let text: Vec<u8> = (0..512u32).map(|i| b'a' + (i * 7 % 26) as u8).collect();
        let mut img = stream(&[(0, &text)]);
        // The grain's deflate stream starts 12 bytes into the marker at 512;
        // damage its second half.
        let len = u32::from_le_bytes(img[520..524].try_into().unwrap()) as usize;
        for b in &mut img[512 + 12 + len / 2..512 + 12 + len] {
            *b ^= 0xFF;
        }
        let mut budget = crate::Budget::new(crate::Limits::default());
        let got = crate::extract(crate::Format::Vmdk, &img.as_slice(), &mut budget).unwrap();
        assert!(got[0]
            .unsupported
            .is_some_and(|w| w.contains("could not be decompressed")));
        let disk = &got[1];
        assert!(disk.unsupported.is_none() && disk.name == "vmdk-disk");
        assert!(disk.data.len() == 512 * 512);
        assert!(
            disk.data.starts_with(&text[..3]),
            "the decoded prefix is kept"
        );
    }

    #[test]
    fn a_stream_with_no_grain_is_reported() {
        assert!(matches!(
            open(&stream(&[]).as_slice(), usize::MAX),
            Opened::Unread(_, w) if w.contains("no grain")
        ));
    }
}
