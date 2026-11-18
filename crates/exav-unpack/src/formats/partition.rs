//! Disk partition-map extraction (raw disk images).
//!
//! Recurses into the partitions of a raw disk image (the `CL_TYPE_GPT` /
//! `CL_TYPE_APM` / `CL_TYPE_MBR` types): each partition's byte range is
//! carved out and emitted as a member for the engine to type and scan (a
//! partition typically holds a filesystem, a nested image, or a bootloader).
//!
//! One module handles all three layouts, dispatching on magic:
//!   * **GPT**: GUID Partition Table (`EFI PART` at LBA1 / offset 512).
//!   * **APM**: Apple Partition Map (`ER` at sector 0, `PM` entries onward).
//!   * **MBR**: classic MBR partition table (conservative: the `55 AA` boot
//!     signature is weak, so we only treat input as MBR when a partition entry
//!     actually looks valid). An extended partition is walked through its chain
//!     of extended boot records (EBR): each logical partition is a region of its
//!     own, so its filesystem is walked like a primary one.
//!
//! Sectors are assumed to be 512 bytes. Every field read here is
//! attacker-controlled, so all offsets use saturating arithmetic and every slice
//! bound is clamped with `.min(data.len())`; the code never panics on hostile or
//! truncated input. The number of partitions read from one table is bounded by
//! the member limit, and each carved region is charged against the [`Budget`]
//! before it is materialised.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use crate::*;

const SECTOR: usize = 512;
/// Sane bounds on the size of a GPT partition entry.
const GPT_MIN_ENTRY_SIZE: u32 = 128;
const GPT_MAX_ENTRY_SIZE: u32 = 4096;

/// The most partitions read from one table: the member limit.
fn max_parts(limits: &Limits) -> usize {
    usize::try_from(limits.max_members).unwrap_or(usize::MAX)
}

const GPT_SIG: &[u8; 8] = b"EFI PART";

/// Where the four entries of an MBR's partition table start.
const MBR_ENTRIES: [usize; 4] = [0x1BE, 0x1CE, 0x1DE, 0x1EE];

/// The partition types of an extended partition: DOS, Windows 98 (LBA) and
/// Linux.
const EXTENDED_TYPES: [u8; 3] = [0x05, 0x0F, 0x85];

/// The number of the first logical partition, as Linux numbers them: after the
/// four that a table can hold.
const FIRST_LOGICAL: usize = 5;

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
/// conservatively-validated MBR). Used by `detect()`, placed last there so the
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

/// Whether any two of `ranges` (start, end) share a byte.
fn overlap(mut ranges: Vec<(u64, u64)>) -> bool {
    ranges.sort_unstable();
    let mut furthest = 0u64;
    for (start, end) in ranges {
        if start < furthest {
            return true;
        }
        furthest = furthest.max(end);
    }
    false
}

/// What a partition table holds.
pub(crate) struct Table {
    pub(crate) regions: Vec<Region>,
    /// The places in `regions` of the logical partitions of an extended
    /// partition.
    logical: Vec<usize>,
    /// The byte ranges of the extended partitions that were walked: the
    /// logical partitions are inside them, so they are not in `regions`.
    extended: Vec<(u64, u64)>,
}

impl Table {
    /// Whether two partitions claim the same sectors. A logical partition
    /// lies inside its extended partition, so the two are not compared; each
    /// is compared with the primary partitions, and the logical ones with each
    /// other. Only real partitions count, not the parts of a table left
    /// unwalked.
    fn intersect(&self) -> bool {
        let mut primary = Vec::new();
        let mut logical = Vec::new();
        for (i, r) in self.regions.iter().enumerate() {
            if let Region::Member(_, start, len) = r
                && *len > 0
            {
                let range = (*start, start.saturating_add(*len));
                match self.logical.contains(&i) {
                    true => logical.push(range),
                    false => primary.push(range),
                }
            }
        }
        let mut members = primary.clone();
        members.extend(logical);
        primary.extend(&self.extended);
        overlap(primary) || overlap(members)
    }
}

/// The ClamAV alert name for an overlapping partition table in `data`, or
/// `None` when the table is well-formed (or is not a partition map at all).
///
/// Two partitions that claim the same sectors are not a thing an installer
/// produces. It is how an image shows one filesystem to the tool that mounts it
/// and another to the tool that scans it: the same parser-confusion idea as
/// overlapping ZIP records, one layer down.
///
/// The three names are ClamAV's exactly, **including the doubled `n` in
/// `MBRPartitionnIntersect`**. That is a typo upstream, but the name is the API:
/// a gateway filtering on it would not match a corrected spelling.
pub fn intersection_alert(
    data: &dyn crate::source::ByteSource,
    limits: &Limits,
) -> Option<&'static str> {
    let table = read_table(&mut crate::source::Reader::new(data), limits).ok()?;
    if !table.intersect() {
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

/// Whether the start of a disk `len` bytes long, `head` (at least two
/// sectors of it, or all of a shorter one), holds a partition table.
#[cfg(feature = "partition")]
pub(crate) fn is_table(head: &[u8], len: u64) -> bool {
    is_gpt(head) || is_apm(head) || is_mbr_in(head, len)
}

/// Walk a disk image, each partition streamed from where it lies. A partition
/// larger than the buffer limit that holds a filesystem exav reads is walked
/// in place instead, where the stream would be all of it.
#[cfg(feature = "partition")]
pub(crate) fn walk(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let regions = stream_offsets(&mut source, budget.limits())?;
    super::volumes::walk_regions(
        &mut source,
        regions,
        super::volumes::Mode::Raw,
        budget,
        visit,
    )
}

/// Parse the GPT/APM/MBR table (tiny, near the start) via targeted reads and
/// return each partition as a region; the partition data, the bulk of a disk
/// image, is streamed by the caller. Ranges are validated against the file
/// length. A part of the table that was not walked is a region of its own,
/// which the caller reports. A table holds no more partitions than the member
/// limit counts, and a GPT entry array no more bytes than the buffer limit
/// holds.
#[cfg(feature = "partition")]
pub(crate) fn stream_offsets(
    source: &mut dyn crate::stream::Disk,
    limits: &Limits,
) -> Result<Vec<Region>, LimitHit> {
    Ok(read_table(source, limits)?.regions)
}

/// [`stream_offsets`], with what the overlap check needs besides the regions.
fn read_table(source: &mut dyn crate::stream::Disk, limits: &Limits) -> Result<Table, LimitHit> {
    const TOO_MANY_GPT: &str = "more GPT partitions than the member and buffer limits \
                                (--max-members, --max-object-bytes) allow; the rest were \
                                not walked";
    let max = max_parts(limits);
    let total_len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("partition: {e}")))?;
    let head = crate::read_at(source, 0, 2 * SECTOR)?; // covers GPT sig, APM ER/PM, MBR table
    let mut out = Vec::new();
    let mut logical = Vec::new();
    let mut extended = Vec::new();
    if is_gpt(&head) {
        let entries_lba = le_u64(&head, SECTOR + 72);
        let declared = le_u32(&head, SECTOR + 80);
        // An implausible stride is not walked, but the partitions are still
        // there.
        let entry_size = le_u32(&head, SECTOR + 84);
        if !(GPT_MIN_ENTRY_SIZE..=GPT_MAX_ENTRY_SIZE).contains(&entry_size) {
            out.push(Region::Unwalked(
                "<gpt>".to_string(),
                "implausible GPT entry size; partition table not walked",
            ));
            return Ok(Table {
                regions: out,
                logical,
                extended,
            });
        }
        // The entry array is read whole. Clamping a parsed count discards the
        // entries past it, so what is discarded is reported.
        let held = limits
            .max_buffer_bytes
            .checked_div(u64::from(entry_size))
            .unwrap_or(0);
        let allowed = max.min(usize::try_from(held).unwrap_or(usize::MAX));
        let num_entries = usize::try_from(declared).unwrap_or(usize::MAX).min(allowed);
        if u64::from(declared) > num_entries as u64 {
            out.push(Region::Unwalked(
                format!("<gpt-partitions-beyond-{allowed}>"),
                TOO_MANY_GPT,
            ));
        }
        let base = entries_lba.saturating_mul(SECTOR as u64);
        // Nothing is read past the end of the image: what the array lacks
        // there is reported below.
        let avail = usize::try_from(total_len.saturating_sub(base)).unwrap_or(usize::MAX);
        let table = crate::read_at(
            source,
            base,
            num_entries.saturating_mul(entry_size as usize).min(avail),
        )?;
        let mut emitted = 0usize;
        for i in 0..num_entries {
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
        let map_entries = usize::try_from(declared_map).unwrap_or(usize::MAX).min(max);
        if u64::from(declared_map) > map_entries as u64 {
            out.push(Region::Unwalked(
                format!("<apm-partitions-beyond-{max}>"),
                "more APM partitions than the member limit (--max-members) allows; the rest \
                 were not walked",
            ));
        }
        let mut emitted = 0usize;
        for i in 0..map_entries {
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
        let mut logicals = 0usize;
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
            if EXTENDED_TYPES.contains(&ptype) {
                let room = max.saturating_sub(emitted).saturating_sub(logicals);
                let number = FIRST_LOGICAL.saturating_add(logicals);
                if let Some(found) =
                    walk_extended(source, lba_first, sectors, total_len, number, room, max)?
                {
                    for r in found {
                        if matches!(r, Region::Member(..)) {
                            logical.push(out.len());
                            logicals = logicals.saturating_add(1);
                        }
                        out.push(r);
                    }
                    let start = lba_first.saturating_mul(SECTOR as u64);
                    let end = lba_first
                        .saturating_add(sectors)
                        .saturating_mul(SECTOR as u64);
                    extended.push((start, end.min(total_len)));
                    continue;
                }
                // Not a chain of boot records: read as any other partition.
            }
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
    Ok(Table {
        regions: out,
        logical,
        extended,
    })
}

/// The logical partitions of the extended partition of `sectors` sectors at
/// sector `first`, in the order of its chain of extended boot records, named
/// from `number`, at most `room` of them, from at most `max_records` boot
/// records. `None` when its first sector is not a boot record: there is no
/// chain to walk.
///
/// Each boot record is a table of four entries. A logical partition starts
/// where its own boot record says, relative to that record. A link to the next
/// boot record is relative to the start of the extended partition, not to the
/// record it is in. A chain that cannot be followed to its end ends with a
/// region that says so.
fn walk_extended(
    source: &mut dyn crate::stream::Disk,
    first: u64,
    sectors: u64,
    total_len: u64,
    number: usize,
    room: usize,
    max_records: usize,
) -> Result<Option<Vec<Region>>, LimitHit> {
    let stop = |why: &'static str| Region::Unwalked(format!("<mbr-extended-{first}>"), why);
    let end = first.saturating_add(sectors);
    let mut found = Vec::new();
    // The logical partitions in `found`.
    let mut kept = 0usize;
    let mut records: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut this = first;
    loop {
        if records.contains(&this) {
            found.push(stop(
                "extended partition whose boot records loop; the rest of it was not walked",
            ));
            break;
        }
        if records.len() >= max_records {
            found.push(stop(
                "more boot records than the member limit (--max-members) allows; the rest was \
                 not walked",
            ));
            break;
        }
        records.insert(this);
        let at = this.saturating_mul(SECTOR as u64);
        let record = match at.saturating_add(SECTOR as u64) <= total_len {
            true => crate::read_at(source, at, SECTOR)?,
            false => Vec::new(),
        };
        if record.len() != SECTOR || record.get(510..512) != Some(&[0x55, 0xAA][..]) {
            if records.len() == 1 {
                return Ok(None);
            }
            found.push(stop(
                "link to something that is not a boot record; the rest of the extended partition was not walked",
            ));
            break;
        }
        let mut next = None;
        for (slot, e) in MBR_ENTRIES.into_iter().enumerate() {
            let ptype = record.get(e.saturating_add(4)).copied().unwrap_or(0);
            let start = le_u32(&record, e.saturating_add(8)) as u64;
            let len = le_u32(&record, e.saturating_add(12)) as u64;
            if ptype == 0x00 || len == 0 {
                continue;
            }
            if EXTENDED_TYPES.contains(&ptype) {
                // The first link is the one that is followed.
                next.get_or_insert(first.saturating_add(start));
                continue;
            }
            let start = this.saturating_add(start);
            // The last two entries of a record often hold garbage: they count
            // only where they lie inside the extended partition.
            if slot >= 2 && (start < first || start.saturating_add(len) > end) {
                continue;
            }
            if kept >= room {
                found.push(stop(
                    "more partitions than the member limit (--max-members) allows; the rest of \
                     the extended partition was not walked",
                ));
                return Ok(Some(found));
            }
            let name = format!("mbr-part-{}", number.saturating_add(kept));
            if let Some(m) = lba_range(name, start, start.saturating_add(len), total_len) {
                found.push(m);
                kept = kept.saturating_add(1);
            }
        }
        match next {
            Some(n) => this = n,
            None => break,
        }
    }
    Ok(Some(found))
}

fn is_gpt(data: &[u8]) -> bool {
    crate::bytes::at(data, SECTOR, 8) == Some(GPT_SIG.as_slice())
}

fn is_apm(data: &[u8]) -> bool {
    // Block0 signature `ER` at sector 0, and a partition-map entry `PM` at
    // sector 1: both required so a stray "ER..." prefix isn't mistaken for APM.
    data.starts_with(b"ER") && crate::bytes::at(data, SECTOR, 2) == Some(b"PM".as_slice())
}

/// Conservative MBR test: the `55 AA` boot signature at offset 510 plus at least
/// one partition-table entry that actually looks like a partition.
/// Does this sector look like a **volume boot record** (the first sector of a
/// filesystem) rather than a partition table?
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
        // past sector 0, which is where the MBR itself lives: a partition
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
    /// Block, and, at 446, ordinary boot code that happens to read as a
    /// partition entry. Modelled on what `mformat` writes.
    fn fat_boot_sector() -> Vec<u8> {
        let mut b = vec![0u8; 2 * SECTOR];
        b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"MTOO4048");
        b[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes per sector
        b[13] = 1; // sectors per cluster
        // Boot code that parses as: bootable, type 0x01 (FAT12), LBA 0, 4096
        // sectors, i.e. a "partition" covering the entire image.
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
        // image: a member identical to its container, which then re-detects the
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
        // A protective MBR (type 0xEE) must yield no MBR members: it defers to
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
            let _ = stream_offsets(&mut std::io::Cursor::new(bytes), &Limits::default());
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

    /// An entry of a table: (type, start, sectors).
    type Slot = (u8, u32, u32);

    /// Write a table of up to four entries into sector `at` of `img`.
    fn put_table(img: &mut [u8], at: usize, entries: &[Slot]) {
        for (i, (ptype, start, len)) in entries.iter().enumerate() {
            let e = at * SECTOR + MBR_ENTRIES[i];
            img[e + 4] = *ptype;
            img[e + 8..e + 12].copy_from_slice(&start.to_le_bytes());
            img[e + 12..e + 16].copy_from_slice(&len.to_le_bytes());
        }
        img[at * SECTOR + 510] = 0x55;
        img[at * SECTOR + 511] = 0xAA;
    }

    /// The regions of `img` as (name, start sector, sectors), and the reports.
    fn layout(img: &[u8]) -> (Vec<(String, u64, u64)>, Vec<&'static str>) {
        layout_within(img, &Limits::default())
    }

    /// [`layout`] under `limits`.
    fn layout_within(img: &[u8], limits: &Limits) -> (Vec<(String, u64, u64)>, Vec<&'static str>) {
        let regions = stream_offsets(&mut std::io::Cursor::new(img), limits).unwrap();
        let mut parts = Vec::new();
        let mut reports = Vec::new();
        for r in regions {
            match r {
                Region::Member(name, off, len) => parts.push((name, off / 512, len / 512)),
                Region::Unwalked(_, why) => reports.push(why),
            }
        }
        (parts, reports)
    }

    /// A disk of 2000 sectors: a primary partition at 10, an extended
    /// partition at 100 of 1500 sectors, and `n` logical partitions. Boot record
    /// k is at sector 100 + 200 * k, where the first logical partition begins 4
    /// sectors on and the others 1, the way a partitioning tool lays them out;
    /// each link is relative to the extended partition and gives the next
    /// record. Each logical partition starts with the marker `L<k>`.
    fn extended_disk(n: usize) -> Vec<u8> {
        let mut img = vec![0u8; 2000 * SECTOR];
        put_table(&mut img, 0, &[(0x83, 10, 20), (0x05, 100, 1500)]);
        for k in 0..n {
            let ebr = 100 + 200 * k;
            let logical = ebr + if k == 0 { 4 } else { 1 };
            let mut t = vec![(0x83, (logical - ebr) as u32, 50)];
            if k + 1 < n {
                t.push((0x05, (200 * (k + 1)) as u32, 51));
            }
            put_table(&mut img, ebr, &t);
            let marker = format!("L{}", k + 1);
            img[logical * SECTOR..logical * SECTOR + marker.len()]
                .copy_from_slice(marker.as_bytes());
        }
        img
    }

    /// The third and later logical partitions are where the chain puts them: a
    /// link is relative to the extended partition, a partition to its own record.
    #[test]
    fn every_logical_partition_of_an_extended_partition_is_a_region() {
        let img = extended_disk(6);
        let (parts, reports) = layout(&img);
        assert!(reports.is_empty(), "{reports:?}");
        let mut want = vec![("mbr-part-1".to_string(), 10, 20)];
        for k in 0..6u64 {
            let at = 100 + 200 * k + if k == 0 { 4 } else { 1 };
            want.push((format!("mbr-part-{}", 5 + k), at, 50));
        }
        assert_eq!(parts, want);

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Partition, &img, &mut budget).unwrap();
        for k in 1..=6 {
            let m = entries
                .iter()
                .find(|e| e.name == format!("mbr-part-{}", 4 + k))
                .unwrap();
            assert!(
                m.data.starts_with(format!("L{k}").as_bytes()),
                "logical {k}"
            );
        }
    }

    /// The extended partition holds the logical ones, and does not overlap them.
    #[test]
    fn an_extended_partition_and_its_logical_partitions_do_not_intersect() {
        let limits = Limits::default();
        let img = extended_disk(6);
        assert_eq!(intersection_alert(&img, &limits), None);
        // A logical partition on the primary one does.
        let mut img = img;
        put_table(&mut img, 100, &[(0x83, 4, 50), (0x05, 200, 51)]);
        put_table(&mut img, 0, &[(0x83, 100 + 4 + 10, 20), (0x05, 100, 1500)]);
        assert_eq!(
            intersection_alert(&img, &limits),
            Some("Heuristics.MBRPartitionnIntersect")
        );
        // Two logical partitions on each other do: the one of the second
        // record (at 301) is made to reach the one of the third (at 501).
        let mut img = extended_disk(6);
        put_table(&mut img, 300, &[(0x83, 1, 300), (0x05, 400, 51)]);
        assert_eq!(
            intersection_alert(&img, &limits),
            Some("Heuristics.MBRPartitionnIntersect")
        );
        // An extended partition over a primary one does.
        let mut img = extended_disk(2);
        put_table(&mut img, 0, &[(0x83, 1200, 20), (0x05, 100, 1500)]);
        assert_eq!(
            intersection_alert(&img, &limits),
            Some("Heuristics.MBRPartitionnIntersect")
        );
    }

    /// A chain that comes back to a record it has been through ends, says so,
    /// and keeps the partitions before it.
    #[test]
    fn a_chain_of_boot_records_that_loops_ends_and_is_reported() {
        let mut img = extended_disk(3);
        // The third record links to the second.
        put_table(&mut img, 500, &[(0x83, 1, 50), (0x05, 200, 51)]);
        let (parts, reports) = layout(&img);
        assert_eq!(parts.len(), 4, "{parts:?}");
        assert_eq!(reports.len(), 1);
        assert!(reports[0].contains("loop"), "{reports:?}");
        // One that links to itself.
        let mut img = extended_disk(1);
        put_table(&mut img, 100, &[(0x83, 4, 50), (0x05, 0, 51)]);
        let (parts, reports) = layout(&img);
        assert_eq!(parts.len(), 2);
        assert!(reports.iter().any(|r| r.contains("loop")), "{reports:?}");
    }

    /// A link to a sector that holds no record is reported, and the partitions
    /// before it are kept. An extended partition whose first sector holds none is
    /// read as a plain partition, as it was before the chains were followed.
    #[test]
    fn a_chain_that_cannot_be_followed_is_reported_not_dropped() {
        let mut img = extended_disk(3);
        img[500 * SECTOR + 510] = 0;
        let (parts, reports) = layout(&img);
        assert_eq!(parts.len(), 3, "{parts:?}");
        assert!(reports.iter().any(|r| r.contains("not a boot record")));

        let mut img = extended_disk(3);
        img[100 * SECTOR + 510] = 0;
        let (parts, reports) = layout(&img);
        assert!(reports.is_empty());
        assert_eq!(
            parts,
            vec![
                ("mbr-part-1".to_string(), 10, 20),
                ("mbr-part-2".to_string(), 100, 1500)
            ]
        );
    }

    /// More logical partitions than the member limit allows is reported, and
    /// with no limit they are all walked.
    #[test]
    fn too_many_logical_partitions_are_reported() {
        let mut limits = Limits {
            max_members: 40,
            ..Limits::default()
        };
        let n = 50;
        let mut img = vec![0u8; (2 * n + 10) * SECTOR];
        put_table(&mut img, 0, &[(0x05, 4, (2 * n) as u32)]);
        for k in 0..n {
            let ebr = 4 + 2 * k;
            let mut t = vec![(0x83, 1, 1)];
            if k + 1 < n {
                t.push((0x05, (2 * (k + 1)) as u32, 2));
            }
            put_table(&mut img, ebr, &t);
        }
        let (parts, reports) = layout_within(&img, &limits);
        assert!(parts.len() < 40, "{}", parts.len());
        assert!(parts.len() > 30, "{}", parts.len());
        assert!(
            reports.iter().any(|r| r.contains("--max-members")),
            "{reports:?}"
        );
        limits.max_members = u64::MAX;
        let (parts, reports) = layout_within(&img, &limits);
        assert_eq!(parts.len(), n, "{}", parts.len());
        assert!(reports.is_empty(), "{reports:?}");
    }

    /// The last two entries of a boot record often hold garbage: they count
    /// only where they lie inside the extended partition. The same entry in
    /// the second slot is a partition.
    #[test]
    fn garbage_in_the_last_two_entries_of_a_boot_record_is_not_a_partition() {
        let mut img = extended_disk(2);
        // The partition of the first record, its link, and a partition that
        // starts at sector 1700 of a disk whose extended partition ends at
        // 1600.
        let (logical, link) = ((0x83, 4, 50), (0x05, 200, 51));
        put_table(&mut img, 100, &[logical, link, (0x83, 1600, 50)]);
        let (parts, reports) = layout(&img);
        assert!(reports.is_empty(), "{reports:?}");
        let names: Vec<_> = parts.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(names, ["mbr-part-1", "mbr-part-5", "mbr-part-6"]);
        // In the second entry the same one is a partition.
        put_table(&mut img, 100, &[logical, (0x83, 1600, 50), link]);
        let (parts, _) = layout(&img);
        assert!(parts.iter().any(|p| p.1 == 1700), "{parts:?}");
    }

    /// A chain of boot records with no partition in them is bounded by the
    /// member limit too: it ends, reported, where the limit is.
    #[test]
    fn a_long_chain_of_empty_boot_records_is_reported() {
        let n = 50;
        let mut img = vec![0u8; (2 * n + 10) * SECTOR];
        put_table(&mut img, 0, &[(0x05, 4, (2 * n) as u32)]);
        for k in 0..n {
            let link = (k + 1 < n).then_some((0x05, (2 * (k + 1)) as u32, 2));
            put_table(&mut img, 4 + 2 * k, &link.into_iter().collect::<Vec<_>>());
        }
        let mut limits = Limits {
            max_members: 40,
            ..Limits::default()
        };
        let (parts, reports) = layout_within(&img, &limits);
        assert!(parts.is_empty(), "{parts:?}");
        assert!(
            reports.iter().any(|r| r.contains("boot records")),
            "{reports:?}"
        );
        limits.max_members = u64::MAX;
        let (_, reports) = layout_within(&img, &limits);
        assert!(reports.is_empty(), "{reports:?}");
    }
}
