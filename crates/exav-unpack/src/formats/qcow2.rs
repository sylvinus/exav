//! QCOW2 — QEMU's copy-on-write disk image.
//!
//! 7-Zip opens these, every hypervisor reads them, and `qemu-img convert -c`
//! produces one whose clusters are **compressed** (deflate, or zstd where the
//! image says so). That last part is what makes the format matter to a scanner
//! rather than merely to a virtualisation stack: a payload inside a compressed
//! image appears nowhere in the file's bytes, so nothing short of real
//! reconstruction reaches it.
//!
//! Implemented from the public QCOW2 specification. All header and table fields
//! are **big-endian**.
//!
//! The disk is addressed through two levels of tables. A guest offset splits
//! into an L1 index, an L2 index and an offset within the cluster; `L1[i]` gives
//! the location of an L2 table, and `L2[j]` gives the location of the cluster
//! itself — or marks it unallocated (reads as zeroes) or compressed. The tables
//! are read from the source as clusters are reached, never held.
//!
//! The disk is a [`VDisk`]: one member when it fits the buffer limit, else its
//! filesystems are walked in place (see `vdisk.rs`).

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use super::vdisk::{self, be64, bytes_at, Health, Layout, Map, Unpacked, VDisk};
use super::volumes::report_enc;
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, LimitHit};

/// L2 entry bit 62: the cluster is compressed.
const L2_COMPRESSED: u64 = 1 << 62;
/// Mask selecting a cluster's host offset from an uncompressed L1/L2 entry.
/// Bits 9..55; the low bits are flags and the top bit is `COPIED`.
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
/// L2 entry bit 0 (qcow2 v3): the cluster reads as zeroes.
const L2_ZERO: u64 = 1;

/// Incompatible-feature bits (version 3, header offset 72) that change how
/// the image is read.
const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPAT_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;
/// Dirty, corrupt, external data file, compression type, extended L2: the
/// bits this reader knows. An image needing another is not read.
const INCOMPAT_KNOWN: u64 = 0b1_1111;

const NAME: &str = "qcow2-disk";

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

/// The low `bits` bits set.
fn low_mask(bits: u32) -> u64 {
    1u64.checked_shl(bits)
        .map_or(u64::MAX, |m| m.saturating_sub(1))
}

pub(crate) fn is_qcow2(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Qcow2)
}

/// How a cluster is compressed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Codec {
    Deflate,
    Zstd,
}

struct Qcow2<'a> {
    src: &'a dyn ByteSource,
    l1: u64,
    cluster: u64,
    l2_entries: u64,
    size: u64,
    file_len: u64,
    codec: Codec,
    /// Compressed-cluster descriptor split, per the specification: the low
    /// `csize_shift` bits are the host offset, the next ones the length in
    /// 512-byte sectors minus one.
    csize_shift: u32,
    csize_mask: u64,
}

impl Layout for Qcow2<'_> {
    fn name(&self) -> &'static str {
        NAME
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn unit(&self) -> u64 {
        self.cluster
    }

    fn map(&self, idx: u64) -> Map {
        let i = idx.checked_div(self.l2_entries).unwrap_or(0);
        let j = idx.checked_rem(self.l2_entries).unwrap_or(0);
        let Some(l1e) = be64(self.src, self.l1.saturating_add(i.saturating_mul(8))) else {
            return Map::Zero;
        };
        let l2 = l1e & OFFSET_MASK;
        if l2 == 0 {
            return Map::Zero; // no L2 table: this whole range is unallocated (zeroes)
        }
        // An L2 table past the end is a truncated image.
        if l2
            .checked_add(self.cluster)
            .is_none_or(|end| end > self.file_len)
        {
            return Map::Zero;
        }
        let Some(e) = be64(self.src, l2.saturating_add(j.saturating_mul(8))) else {
            return Map::Zero;
        };
        let compressed = e & L2_COMPRESSED != 0;
        // Bit 0 means "reads as zeroes" for a *plain* entry only. In a
        // compressed descriptor it is part of the host offset, so testing it
        // unconditionally drops every compressed cluster that happens to
        // start at an odd byte — silently, as a hole of zeroes that scans
        // clean.
        if e == 0 || (!compressed && e & L2_ZERO != 0) {
            return Map::Zero; // unallocated or explicitly zero
        }
        if compressed {
            let at = e & low_mask(self.csize_shift);
            let sectors =
                (e.checked_shr(self.csize_shift).unwrap_or(0) & self.csize_mask).saturating_add(1);
            // The run starts mid-sector, so the first partial sector counts
            // against the total length.
            let len = sectors.saturating_mul(512).saturating_sub(at & 511);
            // Past the end: a truncated image, not a hidden cluster.
            if at >= self.file_len {
                return Map::Zero;
            }
            let avail = self.file_len.saturating_sub(at);
            return Map::Packed {
                at,
                stored: len.min(avail),
                cut: len > avail,
            };
        }
        // A table entry pointing past the end means the image is truncated:
        // those bytes are absent rather than hidden, so the cluster stays zero.
        // An offset of zero is no cluster at all, whatever the flag bits say.
        let host = e & OFFSET_MASK;
        let n = self
            .cluster
            .min(self.size.saturating_sub(idx.saturating_mul(self.cluster)));
        if host == 0 || host.checked_add(n).is_none_or(|end| end > self.file_len) {
            return Map::Zero;
        }
        Map::Plain(host)
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
        let cap = out as u64;
        let s = match self.codec {
            // Clusters are raw DEFLATE, with no zlib wrapper.
            Codec::Deflate => crate::salvage(crate::inflate::Inflate::new(&raw[..]), cap),
            #[cfg(feature = "zstd")]
            Codec::Zstd => {
                use std::io::Read;
                // The compressed run is padded to a sector: the cluster is
                // what the frame holds, and what follows it is not a frame.
                let frames = super::zstd::ZstdReader::new(std::io::Cursor::new(&raw[..]));
                crate::salvage(frames.take(cap), cap)
            }
            #[cfg(not(feature = "zstd"))]
            Codec::Zstd => {
                return Unpacked {
                    data: Vec::new(),
                    damaged: true,
                }
            }
        };
        Unpacked {
            damaged: s.part_way(cut),
            data: s.data,
        }
    }

    fn reports(&self, health: &Health) -> Vec<(u64, &'static str)> {
        // A cluster whose compressed bytes are *present* but will not decode is
        // content exav failed to read — it must be reported. A cluster pointing
        // past the end of the file is content that is not there at all, which
        // is a truncated image rather than a hidden payload, and stays quiet.
        // Reported alongside the disk, not instead of it: zero-filling a failed
        // cluster and saying nothing would hand the scanner clean-looking space
        // where real content should be.
        match health.undecodable() {
            0 => Vec::new(),
            n => vec![(
                n.saturating_mul(self.cluster).min(self.size),
                "QCOW2 compressed clusters that could not be decompressed",
            )],
        }
    }
}

/// What a QCOW2 header makes of an image.
enum Opened<'a> {
    /// Not a QCOW2 image at all.
    No,
    /// A disk to read.
    Disk(Qcow2<'a>),
    /// An image whose disk is not read: the size it declares, whether it is
    /// encrypted, and why.
    Unread(u64, bool, &'static str),
}

/// Read the header of `src`.
fn open(src: &dyn ByteSource) -> Opened<'_> {
    let head = src.window(0, 112);
    if !is_qcow2(&head) {
        return Opened::No;
    }
    let version = be_u32(&head, 4);
    let cluster_bits = be_u32(&head, 20);
    let virtual_size = be_u64(&head, 24);
    let crypt_method = be_u32(&head, 32);
    let l1_size = u64::from(be_u32(&head, 36));
    let l1_offset = be_u64(&head, 40);
    let backing_file_size = be_u32(&head, 16);
    let unread = |why| Opened::Unread(virtual_size, false, why);

    // A backing file holds the clusters this image does not, and it is not in
    // this file — the same shape as a differencing VHD.
    if backing_file_size > 0 {
        return unread(
            "QCOW2 with a backing file: the disk is a delta against an image not in this file",
        );
    }
    if crypt_method != 0 {
        return Opened::Unread(virtual_size, true, "encrypted QCOW2 image");
    }
    let mut codec = Codec::Deflate;
    if version == 3 {
        let incompat = be_u64(&head, 72);
        if incompat & INCOMPAT_EXTERNAL_DATA != 0 {
            return unread(
                "QCOW2 with an external data file: the disk is held in a file not in this one",
            );
        }
        if incompat & INCOMPAT_EXTENDED_L2 != 0 {
            return unread("QCOW2 with extended L2 entries, which exav does not read");
        }
        if incompat & !INCOMPAT_KNOWN != 0 {
            return unread("QCOW2 needing a feature exav does not know");
        }
        if incompat & INCOMPAT_COMPRESSION_TYPE != 0 {
            // Past the header's declared length the field is not there.
            let at = if be_u32(&head, 100) > 104 {
                head.get(104).copied()
            } else {
                Some(0)
            };
            codec = match at {
                Some(0) => Codec::Deflate,
                Some(1) => Codec::Zstd,
                _ => return unread("QCOW2 with a compression type exav does not read"),
            };
        }
    }
    // 9..=21 covers the 512-byte to 2 MiB cluster sizes the format allows; the
    // shift arithmetic below is meaningless outside it.
    if !(9..=21).contains(&cluster_bits) || l1_size == 0 {
        return unread("implausible QCOW2 geometry");
    }
    let cluster = 1u64 << cluster_bits;
    let l2_entries = cluster / 8;

    // The L1 table is read as clusters are reached, but it has to be in the
    // file.
    let file_len = src.len() as u64;
    if !l1_offset
        .checked_add(l1_size.saturating_mul(8))
        .is_some_and(|end| end <= file_len)
    {
        return unread("QCOW2 L1 table lies outside the image");
    }
    let size = virtual_size.min(l1_size.saturating_mul(l2_entries).saturating_mul(cluster));
    Opened::Disk(Qcow2 {
        src,
        l1: l1_offset,
        cluster,
        l2_entries,
        size,
        file_len,
        codec,
        csize_shift: 62u32.saturating_sub(cluster_bits.saturating_sub(8)),
        csize_mask: low_mask(cluster_bits.saturating_sub(8)),
    })
}

/// Walk a QCOW2 image's disk.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    match open(src) {
        Opened::No => Ok(None),
        Opened::Unread(size, encrypted, why) => {
            report_enc(NAME, size, encrypted, why, budget, visit)
        }
        Opened::Disk(layout) => {
            let allowance = budget.remaining_scan();
            vdisk::walk(VDisk::new(src, layout, allowance), budget, visit)
        }
    }
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    /// An image of 64 clusters of 512 bytes: the header at 0, the L1 table at
    /// 512 (one entry, to the L2 table at 1024), and `entry` as the L2 entry of
    /// cluster 0. A data cluster holding `data` is at 1536.
    fn image(version: u32, entry: u64, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 2048];
        f[..4].copy_from_slice(b"QFI\xfb");
        f[4..8].copy_from_slice(&version.to_be_bytes());
        f[20..24].copy_from_slice(&9u32.to_be_bytes());
        f[24..32].copy_from_slice(&(64u64 * 512).to_be_bytes());
        f[36..40].copy_from_slice(&1u32.to_be_bytes());
        f[40..48].copy_from_slice(&512u64.to_be_bytes());
        f[512..520].copy_from_slice(&((1u64 << 63) | 1024).to_be_bytes());
        f[1024..1032].copy_from_slice(&entry.to_be_bytes());
        f[1536..1536 + data.len()].copy_from_slice(data);
        f
    }

    /// A version 3 header with `incompat` set, `len` bytes long, and `ctype`.
    fn v3(incompat: u64, len: u32, ctype: u8) -> Vec<u8> {
        let mut f = image(3, 0, &[]);
        f[72..80].copy_from_slice(&incompat.to_be_bytes());
        f[100..104].copy_from_slice(&len.to_be_bytes());
        f[104] = ctype;
        f
    }

    /// The first `n` bytes of the disk the image opens as, and what was found
    /// of the compressed clusters in reading them.
    fn read(img: &[u8], n: usize) -> (Vec<u8>, u64) {
        let src = &img;
        let Opened::Disk(layout) = open(src) else {
            panic!("the image should open as a disk");
        };
        let mut d = VDisk::new(src, layout, u64::MAX);
        let mut out = vec![0u8; n];
        d.read_exact(&mut out).unwrap();
        (out, d.health().undecodable())
    }

    fn unread(img: &[u8]) -> (bool, &'static str) {
        match open(&img) {
            Opened::Unread(_, enc, why) => (enc, why),
            Opened::Disk(_) => panic!("the image should not open as a disk"),
            Opened::No => panic!("the image should be one"),
        }
    }

    const COPIED: u64 = 1 << 63;

    #[test]
    fn a_plain_cluster_is_read_from_its_offset() {
        let img = image(2, COPIED | 1536, b"payload");
        assert_eq!(&read(&img, 7).0, b"payload");
    }

    /// Bit 0 of a plain entry makes the cluster zeros, whatever it points at.
    #[test]
    fn the_zero_flag_of_a_plain_entry_reads_zeros() {
        let img = image(3, COPIED | 1536 | 1, b"payload");
        assert_eq!(read(&img, 7).0, [0u8; 7]);
    }

    /// An entry with flags and no offset names no cluster. Read as the offset
    /// it is, zero, it would give the file's own header as the disk's first
    /// sector, where the tool that mounts the image reads zeros.
    #[test]
    fn an_entry_with_flags_and_no_offset_is_not_the_file_header() {
        let img = image(2, COPIED, b"payload");
        assert_eq!(read(&img, 4).0, [0u8; 4]);
    }

    /// A cluster that is not wholly in the file is absent, not partly read.
    #[test]
    fn a_cluster_past_the_end_of_the_file_reads_as_zeros() {
        let mut img = image(2, COPIED | 1536, b"payload");
        img.truncate(1536 + 100);
        assert_eq!(read(&img, 7).0, [0u8; 7]);
    }

    /// An L2 table that is not wholly in the file is absent.
    #[test]
    fn an_l2_table_past_the_end_of_the_file_reads_as_zeros() {
        let mut img = image(2, COPIED | 1536, b"payload");
        img[512..520].copy_from_slice(&(COPIED | 1800).to_be_bytes());
        assert_eq!(read(&img, 7).0, [0u8; 7]);
    }

    /// A compressed cluster that will not inflate is counted, and an image cut
    /// inside one is not: what is there is decoded and the rest is absent.
    /// Forty compressed clusters of 2 MiB are 80 MiB decoded, past what the
    /// cache keeps. The first, read again after the rest, is decoded again and
    /// is what it was; the cache never holds more than it may, and what was
    /// decoded is counted.
    #[test]
    fn a_compressed_cluster_read_again_after_eviction_is_the_same() {
        use std::io::Write;
        let (n, cluster) = (40usize, 1usize << 21);
        let pattern =
            |i: usize| -> Vec<u8> { (0..cluster).map(|k| (k % 251) as u8 ^ i as u8).collect() };
        let mut f = vec![0u8; 4 << 20];
        f[..4].copy_from_slice(b"QFI\xfb");
        f[4..8].copy_from_slice(&2u32.to_be_bytes());
        f[20..24].copy_from_slice(&21u32.to_be_bytes());
        f[24..32].copy_from_slice(&((n * cluster) as u64).to_be_bytes());
        f[36..40].copy_from_slice(&1u32.to_be_bytes());
        f[40..48].copy_from_slice(&4096u64.to_be_bytes());
        // The one L2 table is at 2 MiB, wholly in the file.
        f[4096..4104].copy_from_slice(&((1u64 << 63) | (2 << 20)).to_be_bytes());
        for i in 0..n {
            let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            z.write_all(&pattern(i)).unwrap();
            let z = z.finish().unwrap();
            assert!(z.len() < 100_000);
            let at = f.len() as u64;
            let sectors = (at % 512 + z.len() as u64).div_ceil(512);
            let e = (1u64 << 62) | at | ((sectors - 1) << 49);
            f[(2 << 20) + i * 8..(2 << 20) + i * 8 + 8].copy_from_slice(&e.to_be_bytes());
            f.extend_from_slice(&z);
        }
        let src = f.as_slice();
        let Opened::Disk(layout) = open(&src) else {
            panic!("a disk")
        };
        let mut d = VDisk::new(&src, layout, u64::MAX);
        let at = |d: &mut VDisk<'_, Qcow2<'_>>, i: usize| {
            d.seek(SeekFrom::Start((i * cluster + 1000) as u64))
                .unwrap();
            let mut b = vec![0u8; 4096];
            d.read_exact(&mut b).unwrap();
            b
        };
        let first = at(&mut d, 0);
        assert_eq!(first, pattern(0)[1000..5096]);
        for i in 1..n {
            assert_eq!(at(&mut d, i), pattern(i)[1000..5096], "cluster {i}");
        }
        assert_eq!(d.health().decoded(), (n * cluster) as u64);
        assert_eq!(at(&mut d, 0), first, "cluster 0 after it was evicted");
        let h = d.health();
        assert_eq!(h.decoded(), ((n + 1) * cluster) as u64, "decoded again");
        assert_eq!(h.undecodable(), 0);
        assert!(h.cache_peak() <= vdisk::CACHE_BYTES, "{}", h.cache_peak());
    }

    #[test]
    fn a_compressed_cluster_that_will_not_inflate_is_counted() {
        use std::io::Write;
        // One sector at 1536, compressed.
        let entry = (1u64 << 62) | 1536;
        let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        z.write_all(&[b'a'; 512]).unwrap();
        let z = z.finish().unwrap();
        assert!(z.len() > 4 && z.len() < 100);
        let whole = image(2, entry, &z);
        assert_eq!(read(&whole, 512), (vec![b'a'; 512], 0));
        // Bytes that are not deflate.
        let (d, bad) = read(&image(2, entry, &[0xFF; 512]), 512);
        assert_eq!((d, bad), (vec![0u8; 512], 1));
        // The same stream with the file ending inside it: what is there is
        // decoded, the rest is absent, and nothing is left undecoded.
        let mut cut = whole.clone();
        cut.truncate(1536 + z.len() / 2);
        let (d, bad) = read(&cut, 512);
        assert_eq!(bad, 0);
        assert!(d.iter().all(|&b| b == 0 || b == b'a'));
    }

    #[test]
    fn the_features_that_change_how_the_image_is_read_are_not_ignored() {
        assert!(unread(&v3(1 << 2, 104, 0)).1.contains("external data file"));
        assert!(unread(&v3(1 << 4, 104, 0)).1.contains("extended L2"));
        assert!(unread(&v3(1 << 5, 104, 0))
            .1
            .contains("feature exav does not know"));
        assert!(unread(&v3(1 << 3, 112, 9)).1.contains("compression type"));
        // Dirty and corrupt do not change where anything is.
        assert!(matches!(
            open(&v3(0b11, 104, 0).as_slice()),
            Opened::Disk(_)
        ));
        // Zlib named by the feature, or the field absent: deflate.
        assert!(matches!(
            open(&v3(1 << 3, 112, 0).as_slice()),
            Opened::Disk(_)
        ));
        assert!(matches!(
            open(&v3(1 << 3, 104, 1).as_slice()),
            Opened::Disk(_)
        ));
    }

    #[test]
    fn an_image_that_is_not_the_disk_is_reported_with_what_it_declares() {
        let mut img = image(2, 0, &[]);
        img[16..20].copy_from_slice(&5u32.to_be_bytes());
        assert!(unread(&img).1.contains("backing file"));
        let mut img = image(2, 0, &[]);
        img[32..36].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(unread(&img), (true, "encrypted QCOW2 image"));
        for (at, v) in [(20usize, 8u32), (20, 22), (36, 0)] {
            let mut img = image(2, 0, &[]);
            img[at..at + 4].copy_from_slice(&v.to_be_bytes());
            assert!(unread(&img).1.contains("geometry"), "{at} {v}");
        }
    }

    /// A table bigger than the file is refused up front, and one that fits is
    /// not held: the size of the disk is what the tables cover.
    #[test]
    fn the_l1_table_has_to_be_in_the_file_and_bounds_the_disk() {
        let mut img = image(2, 0, &[]);
        img[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(unread(&img).1.contains("L1 table"));
        // Offset near the top of the range: the sum must not wrap.
        let mut img = image(2, 0, &[]);
        img[40..48].copy_from_slice(&(u64::MAX - 3).to_be_bytes());
        assert!(unread(&img).1.contains("L1 table"));
        // A size beyond what one L1 entry covers is cut to it.
        let mut img = image(2, 0, &[]);
        img[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
        let src = img.as_slice();
        let Opened::Disk(l) = open(&src) else {
            panic!()
        };
        assert_eq!(l.size(), 64 * 512);
    }
}
