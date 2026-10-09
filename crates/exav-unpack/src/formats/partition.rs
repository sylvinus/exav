//! Disk partition-map extraction (raw disk images).
//!
//! Recurses into the partitions of a raw disk image (the `CL_TYPE_GPT` /
//! `CL_TYPE_APM` / `CL_TYPE_MBR` types): each partition's byte range is
//! carved out and emitted as a member for the engine to type and scan (a
//! partition typically holds a filesystem, a nested image, or a bootloader).
//!
//! One module handles all three layouts, dispatching on magic:
//!   * **GPT** — GUID Partition Table (`EFI PART` at LBA1 / offset 512).
//!   * **APM** — Apple Partition Map (`ER` at sector 0, `PM` entries onward).
//!   * **MBR** — classic MBR partition table (conservative: the `55 AA` boot
//!     signature is weak, so we only treat input as MBR when a partition entry
//!     actually looks valid).
//!
//! Sectors are assumed to be 512 bytes. Every field read here is
//! attacker-controlled, so all offsets use saturating arithmetic and every slice
//! bound is clamped with `.min(data.len())`; the code never panics on hostile or
//! truncated input. The number of emitted partitions is capped, and each carved
//! region is charged against the [`Budget`] before it is materialised.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use crate::*;

const SECTOR: usize = 512;
/// Hard cap on partitions emitted from a single image (across GPT/APM/MBR).
const MAX_PARTS: usize = 128;
/// Sane bounds on the GPT partition-entry array.
const GPT_MAX_ENTRIES: u32 = MAX_PARTS as u32;
const GPT_MIN_ENTRY_SIZE: u32 = 128;
const GPT_MAX_ENTRY_SIZE: u32 = 4096;

const GPT_SIG: &[u8; 8] = b"EFI PART";

/// Where the four entries of an MBR's partition table start.
const MBR_ENTRIES: [usize; 4] = [0x1BE, 0x1CE, 0x1DE, 0x1EE];

/// Read a little-endian `u64` at `off`, or `0` if out of bounds.
fn le_u64(d: &[u8], off: usize) -> u64 {
    crate::bytes::at(d, off, 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
/// Read a little-endian `u32` at `off`, or `0` if out of bounds.
fn le_u32(d: &[u8], off: usize) -> u32 {
    crate::bytes::at(d, off, 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
/// Read a little-endian `u16` at `off`, or `0` if out of bounds.
fn le_u16(d: &[u8], off: usize) -> u16 {
    crate::bytes::at(d, off, 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
/// Read a big-endian `u32` at `off`, or `0` if out of bounds (APM is big-endian).
fn be_u32(d: &[u8], off: usize) -> u32 {
    crate::bytes::at(d, off, 4)
        .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// True if `data` looks like a partitioned disk image (GPT, APM, or a
/// conservatively-validated MBR). Used by `detect()` — placed last there so the
/// weak MBR boot signature never shadows a more specific format.
#[cfg(feature = "partition")]
pub(crate) fn is_partition(p: &crate::Probe) -> bool {
    is_gpt(p.head) || is_apm(p.head) || is_mbr_in(p.head, p.len as u64)
}

/// One partition as a byte range `[first_lba*512, end_sector*512)` clamped to
/// `total_len`; `None` for a degenerate/out-of-range slice.
fn lba_range(name: String, first_lba: u64, end_sector: u64, total_len: u64) -> Option<Region> {
    let start = first_lba.saturating_mul(SECTOR as u64).min(total_len);
    let end = end_sector.saturating_mul(SECTOR as u64).min(total_len);
    if end <= start {
        return None;
    }
    Some(Region::Member(name, start, end.saturating_sub(start)))
}

/// The ClamAV alert name for an overlapping partition table in `data`, or
/// `None` when the table is well-formed (or is not a partition map at all).
///
/// Two partitions that claim the same sectors are not a thing an installer
/// produces. It is how an image shows one filesystem to the tool that mounts it
/// and another to the tool that scans it — the same parser-confusion idea as
/// overlapping ZIP records, one layer down.
///
/// The three names are ClamAV's exactly, **including the doubled `n` in
/// `MBRPartitionnIntersect`**. That is a typo upstream, but the name is the API:
/// a gateway filtering on it would not match a corrected spelling.
pub fn intersection_alert(data: &dyn crate::source::ByteSource) -> Option<&'static str> {
    let regions = stream_offsets(&mut crate::source::Reader::new(data)).ok()?;
    // Only real partitions count, not the parts of a table left unwalked.
    let mut ranges: Vec<(u64, u64)> = regions
        .iter()
        .filter_map(|r| match r {
            Region::Member(_, start, len) if *len > 0 => Some((*start, start.saturating_add(*len))),
            _ => None,
        })
        .collect();
    if ranges.len() < 2 {
        return None;
    }
    ranges.sort_unstable();
    let mut furthest = 0u64;
    let mut intersects = false;
    for (start, end) in ranges {
        if start < furthest {
            intersects = true;
            break;
        }
        furthest = furthest.max(end);
    }
    if !intersects {
        return None;
    }
    let head = data.window(0, 2 * SECTOR);
    let head = &head[..];
    if is_gpt(head) {
        Some("Heuristics.GPTPartitionIntersection")
    } else if is_apm(head) {
        Some("Heuristics.APMPartitionIntersection")
    } else {
        Some("Heuristics.MBRPartitionnIntersect")
    }
}

/// Walk a disk image, each partition streamed from where it lies.
#[cfg(feature = "partition")]
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let members = stream_offsets(&mut source)?;
    crate::stream::stream_stored(&mut source, budget, visit, members)
}

/// Parse the GPT/APM/MBR table (tiny, near the start) via targeted reads and
/// return each partition as a region; the partition data, the bulk of a disk
/// image, is streamed by the caller. Ranges are validated against the file
/// length. A part of the table that was not walked is a region of its own,
/// which the caller reports.
pub(crate) fn stream_offsets<R: std::io::Read + std::io::Seek>(
    source: &mut R,
) -> Result<Vec<Region>, LimitHit> {
    const TOO_MANY_GPT: &str = "too many GPT partitions to walk them all";
    let total_len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("partition: {e}")))?;
    let head = crate::read_at(source, 0, 2 * SECTOR)?; // covers GPT sig, APM ER/PM, MBR table
    let mut out = Vec::new();
    if is_gpt(&head) {
        let entries_lba = le_u64(&head, SECTOR + 72);
        // Clamping a parsed count discards the entries past the cap, so the
        // cap is reported.
        let declared = le_u32(&head, SECTOR + 80);
        let num_entries = declared.min(GPT_MAX_ENTRIES);
        if declared > GPT_MAX_ENTRIES {
            out.push(Region::Unwalked(
                format!("<gpt-partitions-beyond-{GPT_MAX_ENTRIES}>"),
                TOO_MANY_GPT,
            ));
        }
        // An implausible stride is not walked, but the partitions are still
        // there.
        let entry_size = le_u32(&head, SECTOR + 84);
        if !(GPT_MIN_ENTRY_SIZE..=GPT_MAX_ENTRY_SIZE).contains(&entry_size) {
            out.push(Region::Unwalked(
                "<gpt>".to_string(),
                "implausible GPT entry size; partition table not walked",
            ));
            return Ok(out);
        }
        let base = entries_lba.saturating_mul(SECTOR as u64);
        let table = crate::read_at(
            source,
            base,
            (num_entries as usize).saturating_mul(entry_size as usize),
        )?;
        let mut emitted = 0usize;
        for i in 0..num_entries as usize {
            if emitted >= MAX_PARTS {
                out.push(Region::Unwalked(
                    format!("<gpt-partitions-beyond-{MAX_PARTS}>"),
                    TOO_MANY_GPT,
                ));
                break;
            }
            let e = i.saturating_mul(entry_size as usize);
            // An entry table running past the end: the partitions it describes
            // exist in the layout but cannot be read here.
            let Some(entry) = table.get(e..e.saturating_add(56)) else {
                out.push(Region::Unwalked(
                    "<gpt-entry-table-truncated>".to_string(),
                    "GPT partition entry table extends past the end of the image",
                ));
                break;
            };
            if entry[..16].iter().all(|&b| b == 0) {
                continue;
            }
            let first_lba = le_u64(entry, 32);
            let end_sector = le_u64(entry, 40).saturating_add(1);
            emitted = emitted.saturating_add(1);
            if let Some(m) = lba_range(
                format!("gpt-part-{emitted}"),
                first_lba,
                end_sector,
                total_len,
            ) {
                out.push(m);
            }
        }
    } else if is_apm(&head) {
        let declared_map = be_u32(&head, SECTOR + 4);
        let map_entries = declared_map.min(MAX_PARTS as u32);
        if declared_map > MAX_PARTS as u32 {
            out.push(Region::Unwalked(
                format!("<apm-partitions-beyond-{MAX_PARTS}>"),
                "too many APM partitions to walk them all",
            ));
        }
        let mut emitted = 0usize;
        for i in 0..map_entries as usize {
            if emitted >= MAX_PARTS {
                break;
            }
            let at = (i as u64).saturating_add(1).saturating_mul(SECTOR as u64);
            let sector = crate::read_at(source, at, SECTOR)?;
            if sector.get(0..2) != Some(b"PM".as_slice()) {
                break;
            }
            let pblock_start = be_u32(&sector, 8) as u64;
            let pblock_count = be_u32(&sector, 12) as u64;
            if pblock_count == 0 {
                continue;
            }
            emitted = emitted.saturating_add(1);
            if let Some(m) = lba_range(
                format!("apm-part-{emitted}"),
                pblock_start,
                pblock_start.saturating_add(pblock_count),
                total_len,
            ) {
                out.push(m);
            }
        }
    } else if is_mbr_in(&head, total_len) {
        let mut emitted = 0usize;
        for e in MBR_ENTRIES {
            let ptype = head.get(e.saturating_add(4)).copied().unwrap_or(0);
            if ptype == 0x00 || ptype == 0xEE {
                continue;
            }
            let lba_first = le_u32(&head, e.saturating_add(8)) as u64;
            let sectors = le_u32(&head, e.saturating_add(12)) as u64;
            if sectors == 0 || lba_first.saturating_mul(SECTOR as u64) >= total_len {
                continue;
            }
            emitted = emitted.saturating_add(1);
            if let Some(m) = lba_range(
                format!("mbr-part-{emitted}"),
                lba_first,
                lba_first.saturating_add(sectors),
                total_len,
            ) {
                out.push(m);
            }
        }
    }
    Ok(out)
}

fn is_gpt(data: &[u8]) -> bool {
    data.get(SECTOR..SECTOR + 8) == Some(GPT_SIG.as_slice())
}

fn is_apm(data: &[u8]) -> bool {
    // Block0 signature `ER` at sector 0, and a partition-map entry `PM` at
    // sector 1 — both required so a stray "ER..." prefix isn't mistaken for APM.
    data.starts_with(b"ER") && data.get(SECTOR..SECTOR + 2) == Some(b"PM".as_slice())
}

/// Conservative MBR test: the `55 AA` boot signature at offset 510 plus at least
/// one partition-table entry that actually looks like a partition.
/// Does this sector look like a **volume boot record** — the first sector of a
/// filesystem — rather than a partition table?
///
/// Both end in `55 AA` at offset 510, and a VBR's boot code occupies exactly the
/// bytes where an MBR keeps its partition table, so boot code can read as a
/// plausible partition entry. Getting this wrong is not a harmless false
/// positive: the "partition" it invents can span the whole image, and a member
/// identical to its container recurses until the depth limit, spending the
/// budget that the filesystem's real contents needed.
///
/// The BIOS Parameter Block is what separates them. An MBR has no BPB; a FAT or
/// NTFS VBR has a printable OEM name at offset 3 and a sector/cluster geometry
/// that has to be powers of two in a narrow range.
fn is_volume_boot_record(data: &[u8]) -> bool {
    let Some(oem) = data.get(3..11) else {
        return false;
    };
    if !oem.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return false;
    }
    // exFAT zeroes the classic BPB fields, so it is recognised by name.
    if oem.starts_with(b"EXFAT") {
        return true;
    }
    let bytes_per_sector = le_u16(data, 11);
    let sectors_per_cluster = data.get(13).copied().unwrap_or(0);
    matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && sectors_per_cluster > 0
        && sectors_per_cluster <= 128
        && sectors_per_cluster.is_power_of_two()
}

/// Whether an image `len` bytes long, whose first sector is in `data`, opens
/// with a plausible MBR partition table.
fn is_mbr_in(data: &[u8], len: u64) -> bool {
    if data.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return false;
    }
    if is_volume_boot_record(data) {
        return false;
    }
    MBR_ENTRIES.into_iter().any(|e| {
        let status = data.get(e).copied().unwrap_or(0xFF);
        let ptype = data.get(e.saturating_add(4)).copied().unwrap_or(0);
        let lba_first = le_u32(data, e.saturating_add(8));
        let sectors = le_u32(data, e.saturating_add(12));
        // status must be 0x00 (inactive) or 0x80 (bootable); a non-empty,
        // non-protective type; a non-zero size; a start that lands inside the
        // image (so random bytes with 55 AA at 510 don't qualify); and a start
        // past sector 0, which is where the MBR itself lives — a partition
        // claiming to begin there would carve the whole image, including this
        // very sector, and recurse into itself.
        (status == 0x00 || status == 0x80)
            && ptype != 0x00
            && ptype != 0xEE
            && sectors > 0
            && lba_first > 0
            && (lba_first as u64).saturating_mul(SECTOR as u64) < len
    })
}

// The module compiles unconditionally (for the intersection heuristic), but
// these drive `extract(Format::Partition, …)`, which needs the walker.
// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(all(test, feature = "partition"))]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    /// A FAT boot sector: a jump instruction, an OEM name, a BIOS Parameter
    /// Block — and, at 446, ordinary boot code that happens to read as a
    /// partition entry. Modelled on what `mformat` writes.
    fn fat_boot_sector() -> Vec<u8> {
        let mut b = vec![0u8; 2 * SECTOR];
        b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"MTOO4048");
        b[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
        b[13] = 1; // sectors per cluster
                   // Boot code that parses as: bootable, type 0x01 (FAT12), LBA 0, 4096
                   // sectors — i.e. a "partition" covering the entire image.
        b[446] = 0x80;
        b[446 + 4] = 0x01;
        b[446 + 8..446 + 12].copy_from_slice(&0u32.to_le_bytes());
        b[446 + 12..446 + 16].copy_from_slice(&4096u32.to_le_bytes());
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    #[test]
    fn a_filesystem_boot_sector_is_not_a_partition_table() {
        // Both a volume boot record and an MBR end in `55 AA`, and a VBR's boot
        // code sits exactly where an MBR keeps its partition table. Reading one
        // as the other invents a partition starting at LBA 0 that spans the whole
        // image — a member identical to its container, which then re-detects the
        // same way until the recursion limit is spent. The filesystem's real
        // contents never get reached: a FAT image holding a zipped payload came
        // back LIMITS-EXCEEDED instead of infected.
        assert!(
            !is_partition(&crate::Probe::whole(&fat_boot_sector())),
            "a FAT boot sector must not be taken for a partition table"
        );
    }

    #[test]
    fn a_partition_claiming_to_start_at_sector_zero_is_rejected() {
        // Sector 0 is where the MBR itself lives, so no real partition begins
        // there. Such an entry can only carve the whole image, including the
        // table being read.
        let mut b = vec![0u8; 2 * SECTOR];
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b[446] = 0x80;
        b[446 + 4] = 0x0C;
        b[446 + 8..446 + 12].copy_from_slice(&0u32.to_le_bytes());
        b[446 + 12..446 + 16].copy_from_slice(&2u32.to_le_bytes());
        assert!(!is_mbr_in(&b, b.len() as u64));

        // The same entry one sector in is a normal partition.
        b[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        assert!(is_mbr_in(&b, b.len() as u64));
    }

    use super::*;

    const MARKER: &[u8] = b"MALWARETEST";

    /// Build a minimal GPT image: sector 0 MBR filler, GPT header at sector 1,
    /// a one-entry array at sector 2, and a partition region at sector 3 holding
    /// the marker.
    fn build_gpt() -> Vec<u8> {
        let mut img = vec![0u8; 4 * SECTOR];
        // GPT header at sector 1.
        let h = SECTOR;
        img[h..h + 8].copy_from_slice(GPT_SIG);
        img[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entries_lba = 2
        img[h + 80..h + 84].copy_from_slice(&1u32.to_le_bytes()); // num_entries = 1
        img[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry_size = 128
                                                                    // Partition entry at sector 2.
        let e = 2 * SECTOR;
        img[e] = 0xAB; // non-zero type GUID => used
        img[e + 32..e + 40].copy_from_slice(&3u64.to_le_bytes()); // first_lba = 3
        img[e + 40..e + 48].copy_from_slice(&3u64.to_le_bytes()); // last_lba  = 3
                                                                  // Partition region at sector 3.
        img[3 * SECTOR..3 * SECTOR + MARKER.len()].copy_from_slice(MARKER);
        img
    }

    /// Build a minimal MBR image: one partition entry at 0x1BE pointing at
    /// sector 1, boot signature at 510, marker in sector 1.
    fn build_mbr() -> Vec<u8> {
        let mut img = vec![0u8; 2 * SECTOR];
        let e = 0x1BE;
        img[e] = 0x80; // bootable
        img[e + 4] = 0x0C; // type: FAT32 LBA
        img[e + 8..e + 12].copy_from_slice(&1u32.to_le_bytes()); // lba_first = 1
        img[e + 12..e + 16].copy_from_slice(&1u32.to_le_bytes()); // sector_count = 1
        img[510] = 0x55;
        img[511] = 0xAA;
        img[SECTOR..SECTOR + MARKER.len()].copy_from_slice(MARKER);
        img
    }

    fn members_contain_marker(entries: &[Entry]) -> bool {
        entries
            .iter()
            .any(|m| m.data.windows(MARKER.len()).any(|w| w == MARKER))
    }

    #[test]
    fn detects_all_three() {
        assert_eq!(detect(&build_gpt()), Some(Format::Partition));
        assert_eq!(detect(&build_mbr()), Some(Format::Partition));
        // APM: `ER` at 0 and `PM` at sector 1.
        let mut apm = vec![0u8; 2 * SECTOR];
        apm[..2].copy_from_slice(b"ER");
        apm[SECTOR..SECTOR + 2].copy_from_slice(b"PM");
        assert_eq!(detect(&apm), Some(Format::Partition));
    }

    #[test]
    fn gpt_partition_extracted() {
        let img = build_gpt();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Partition, &img, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "gpt-part-1");
        assert!(members_contain_marker(&entries), "marker not in GPT member");
    }

    #[test]
    fn mbr_partition_extracted() {
        let img = build_mbr();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Partition, &img, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "mbr-part-1");
        assert!(members_contain_marker(&entries), "marker not in MBR member");
    }

    #[test]
    fn apm_partition_extracted() {
        // Block0 `ER`; one map entry at sector 1 (mapEntries=1) covering sector 2.
        let mut img = vec![0u8; 3 * SECTOR];
        img[..2].copy_from_slice(b"ER");
        let e = SECTOR;
        img[e..e + 2].copy_from_slice(b"PM");
        img[e + 4..e + 8].copy_from_slice(&1u32.to_be_bytes()); // mapEntries = 1
        img[e + 8..e + 12].copy_from_slice(&2u32.to_be_bytes()); // pblockStart = 2
        img[e + 12..e + 16].copy_from_slice(&1u32.to_be_bytes()); // pblockCount = 1
        img[2 * SECTOR..2 * SECTOR + MARKER.len()].copy_from_slice(MARKER);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Partition, &img, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "apm-part-1");
        assert!(members_contain_marker(&entries), "marker not in APM member");
    }

    #[test]
    fn protective_mbr_is_skipped() {
        // A protective MBR (type 0xEE) must yield no MBR members — it defers to
        // the GPT that follows.
        let mut img = vec![0u8; 2 * SECTOR];
        let e = 0x1BE;
        img[e + 4] = 0xEE;
        img[e + 8..e + 12].copy_from_slice(&1u32.to_le_bytes());
        img[e + 12..e + 16].copy_from_slice(&1u32.to_le_bytes());
        img[510] = 0x55;
        img[511] = 0xAA;
        // No GPT magic present, so is_partition is false (only a protective entry).
        assert_eq!(detect(&img), None);
    }

    #[test]
    fn garbage_and_truncated_do_not_panic() {
        // Call the table walk directly (no catch_unwind) so a genuine panic would
        // fail the test rather than being swallowed by the containment boundary.
        let run = |bytes: &[u8]| {
            let _ = stream_offsets(&mut std::io::Cursor::new(bytes));
        };
        // Random-ish bytes with the boot signature at 510.
        let mut g = vec![0u8; 1024];
        for (i, b) in g.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        g[510] = 0x55;
        g[511] = 0xAA;
        run(&g);
        // Truncated GPT: magic only, no header body / entries.
        let mut t = vec![0u8; SECTOR + 8];
        t[SECTOR..SECTOR + 8].copy_from_slice(GPT_SIG);
        run(&t);
        // GPT header claiming a huge entry count / out-of-range array LBA.
        let mut h = vec![0u8; SECTOR + 96];
        h[SECTOR..SECTOR + 8].copy_from_slice(GPT_SIG);
        h[SECTOR + 72..SECTOR + 80].copy_from_slice(&u64::MAX.to_le_bytes());
        h[SECTOR + 80..SECTOR + 84].copy_from_slice(&u32::MAX.to_le_bytes());
        h[SECTOR + 84..SECTOR + 88].copy_from_slice(&128u32.to_le_bytes());
        run(&h);
        // Empty and tiny inputs.
        run(&[]);
        run(&[0x55, 0xAA]);
        // Fully random 4 KiB (no valid structure).
        // Compute the mix in u64 (i*constant overflows a 32-bit usize on wasm32).
        let r: Vec<u8> = (0..4096u64)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();
        run(&r);
    }
}
