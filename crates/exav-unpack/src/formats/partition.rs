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

use crate::*;

const SECTOR: usize = 512;
/// Hard cap on partitions emitted from a single image (across GPT/APM/MBR).
const MAX_PARTS: usize = 128;
/// Sane bounds on the GPT partition-entry array.
const GPT_MAX_ENTRIES: u32 = MAX_PARTS as u32;
const GPT_MIN_ENTRY_SIZE: u32 = 128;
const GPT_MAX_ENTRY_SIZE: u32 = 4096;

const GPT_SIG: &[u8; 8] = b"EFI PART";

/// Read a little-endian `u64` at `off`, or `0` if out of bounds.
fn le_u64(d: &[u8], off: usize) -> u64 {
    d.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
/// Read a little-endian `u32` at `off`, or `0` if out of bounds.
fn le_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
/// Read a big-endian `u32` at `off`, or `0` if out of bounds (APM is big-endian).
fn be_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// True if `data` looks like a partitioned disk image (GPT, APM, or a
/// conservatively-validated MBR). Used by `detect()` — placed last there so the
/// weak MBR boot signature never shadows a more specific format.
pub(crate) fn is_partition(data: &[u8]) -> bool {
    is_gpt(data) || is_apm(data) || is_mbr(data)
}

/// Read `len` bytes at `off` from a seekable source (tolerant of short reads).
fn read_at<R: std::io::Read + std::io::Seek>(source: &mut R, off: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    if source.seek(std::io::SeekFrom::Start(off)).is_err() {
        return Vec::new();
    }
    let mut n = 0;
    while n < len {
        match source.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    buf.truncate(n);
    buf
}

/// One partition as a byte range `[first_lba*512, end_sector*512)` clamped to
/// `total_len`; `None` for a degenerate/out-of-range slice.
fn lba_range(
    name: String,
    first_lba: u64,
    end_sector: u64,
    total_len: u64,
) -> Option<(String, u64, u64)> {
    let start = first_lba.saturating_mul(SECTOR as u64).min(total_len);
    let end = end_sector.saturating_mul(SECTOR as u64).min(total_len);
    if end <= start {
        return None;
    }
    Some((name, start, end - start))
}

/// Reader-based streaming: parse the GPT/APM/MBR table (tiny, near the start) via
/// targeted reads and return each partition as `(name, offset, size)`. The
/// partition data itself — which is the bulk of a disk image — streams via
/// seek+take. Mirrors [`extract_partition`]'s ranges, validated against the true
/// file length rather than an in-memory buffer.
pub(crate) fn stream_offsets<R: std::io::Read + std::io::Seek>(
    source: &mut R,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let total_len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("partition: {e}")))?;
    let head = read_at(source, 0, 2 * SECTOR); // covers GPT sig, APM ER/PM, MBR table
    let mut out = Vec::new();
    if is_gpt(&head) {
        let entries_lba = le_u64(&head, SECTOR + 72);
        let num_entries = le_u32(&head, SECTOR + 80).min(GPT_MAX_ENTRIES);
        let entry_size = le_u32(&head, SECTOR + 84);
        if !(GPT_MIN_ENTRY_SIZE..=GPT_MAX_ENTRY_SIZE).contains(&entry_size) {
            return Ok(out);
        }
        let base = entries_lba.saturating_mul(SECTOR as u64);
        let table = read_at(
            source,
            base,
            (num_entries as usize).saturating_mul(entry_size as usize),
        );
        let mut emitted = 0usize;
        for i in 0..num_entries as usize {
            if emitted >= MAX_PARTS {
                break;
            }
            let e = i.saturating_mul(entry_size as usize);
            let Some(entry) = table.get(e..e.saturating_add(56)) else {
                break;
            };
            if entry[..16].iter().all(|&b| b == 0) {
                continue;
            }
            let first_lba = le_u64(entry, 32);
            let end_sector = le_u64(entry, 40).saturating_add(1);
            emitted += 1;
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
        let map_entries = be_u32(&head, SECTOR + 4).min(MAX_PARTS as u32);
        let mut emitted = 0usize;
        for i in 0..map_entries as usize {
            if emitted >= MAX_PARTS {
                break;
            }
            let sector = read_at(source, ((i + 1) * SECTOR) as u64, SECTOR);
            if sector.get(0..2) != Some(b"PM".as_slice()) {
                break;
            }
            let pblock_start = be_u32(&sector, 8) as u64;
            let pblock_count = be_u32(&sector, 12) as u64;
            if pblock_count == 0 {
                continue;
            }
            emitted += 1;
            if let Some(m) = lba_range(
                format!("apm-part-{emitted}"),
                pblock_start,
                pblock_start.saturating_add(pblock_count),
                total_len,
            ) {
                out.push(m);
            }
        }
    } else if head.get(510..512) == Some(&[0x55, 0xAA][..])
        && (0..4).any(|i| {
            // is_mbr, but ranges validated against the true file length rather
            // than the 1 KiB head, so a real (large) MBR image still qualifies.
            let e = 0x1BE + i * 16;
            let status = head.get(e).copied().unwrap_or(0xFF);
            let ptype = head.get(e + 4).copied().unwrap_or(0);
            let lba_first = le_u32(&head, e + 8) as u64;
            let sectors = le_u32(&head, e + 12);
            (status == 0x00 || status == 0x80)
                && ptype != 0x00
                && ptype != 0xEE
                && sectors > 0
                && lba_first.saturating_mul(SECTOR as u64) < total_len
        })
    {
        let mut emitted = 0usize;
        for i in 0..4 {
            let e = 0x1BE + i * 16;
            let ptype = head.get(e + 4).copied().unwrap_or(0);
            if ptype == 0x00 || ptype == 0xEE {
                continue;
            }
            let lba_first = le_u32(&head, e + 8) as u64;
            let sectors = le_u32(&head, e + 12) as u64;
            if sectors == 0 || lba_first.saturating_mul(SECTOR as u64) >= total_len {
                continue;
            }
            emitted += 1;
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
fn is_mbr(data: &[u8]) -> bool {
    if data.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return false;
    }
    (0..4).any(|i| {
        let e = 0x1BE + i * 16;
        let status = data.get(e).copied().unwrap_or(0xFF);
        let ptype = data.get(e + 4).copied().unwrap_or(0);
        let lba_first = le_u32(data, e + 8);
        let sectors = le_u32(data, e + 12);
        // status must be 0x00 (inactive) or 0x80 (bootable); a non-empty,
        // non-protective type; a non-zero size; and a start that lands inside
        // the image (so random bytes with 55 AA at 510 don't qualify).
        (status == 0x00 || status == 0x80)
            && ptype != 0x00
            && ptype != 0xEE
            && sectors > 0
            && (lba_first as usize).saturating_mul(SECTOR) < data.len()
    })
}

/// Carve `[start_sector*512 .. end_sector*512]` (both clamped to the image),
/// charge it against the budget, and hand it to the visitor. Returns
/// `Ok(Some(r))` if the visitor stopped early. Empty/degenerate ranges are
/// skipped without consuming a file-count slot.
fn emit_region<R>(
    data: &[u8],
    name: String,
    start_sector: u64,
    end_sector: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let start = (start_sector as usize)
        .saturating_mul(SECTOR)
        .min(data.len());
    let end = (end_sector as usize).saturating_mul(SECTOR).min(data.len());
    let slice = data.get(start..end).unwrap_or(&[]);
    if slice.is_empty() {
        return Ok(None);
    }
    budget.count_entry()?;
    let cap = budget.reserve()?;
    if slice.len() as u64 > cap {
        return Err(LimitHit::new(format!("partition '{name}' exceeds budget")));
    }
    budget.commit(slice.len() as u64);
    Ok(visit(Entry::new(name, slice.to_vec()), budget))
}

pub(crate) fn extract_partition<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Prefer GPT/APM (self-describing, strong magic); fall back to the
    // conservatively-validated MBR table (which also covers the hybrid case
    // where a real MBR precedes a GPT but the GPT magic is absent/damaged).
    if is_gpt(data) {
        extract_gpt(data, budget, visit)
    } else if is_apm(data) {
        extract_apm(data, budget, visit)
    } else if is_mbr(data) {
        extract_mbr(data, budget, visit)
    } else {
        Ok(None)
    }
}

/// GPT: header at offset 512 gives the partition-entry array location, count,
/// and stride. Each used entry (non-zero type GUID) carves its LBA range.
fn extract_gpt<R>(data: &[u8], budget: &mut Budget, visit: Sink<R>) -> Result<Option<R>, LimitHit> {
    let hdr = SECTOR; // GPT header lives in LBA1.
                      // Real GPT header field offsets (relative to the header start):
                      //   +72 partition_entries_lba (u64)
                      //   +80 num_entries (u32)
                      //   +84 entry_size (u32)
    let entries_lba = le_u64(data, hdr + 72);
    let num_entries = le_u32(data, hdr + 80).min(GPT_MAX_ENTRIES);
    let entry_size = le_u32(data, hdr + 84);
    if !(GPT_MIN_ENTRY_SIZE..=GPT_MAX_ENTRY_SIZE).contains(&entry_size) {
        return Ok(None); // implausible stride — refuse to walk it
    }
    let base = (entries_lba as usize).saturating_mul(SECTOR);
    let mut emitted = 0usize;
    for i in 0..num_entries as usize {
        if emitted >= MAX_PARTS {
            break;
        }
        let e = base.saturating_add(i.saturating_mul(entry_size as usize));
        // An entry we can't fully read (past EOF) ends the walk.
        let Some(entry) = data.get(e..e.saturating_add(56)) else {
            break;
        };
        // All-zero type GUID marks an unused slot.
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first_lba = le_u64(entry, 32);
        let last_lba = le_u64(entry, 40);
        // Range is inclusive of last_lba: [first_lba*512 .. (last_lba+1)*512].
        let end_sector = last_lba.saturating_add(1);
        emitted += 1;
        let name = format!("gpt-part-{emitted}");
        if let Some(r) = emit_region(data, name, first_lba, end_sector, budget, visit)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// APM (big-endian): sector 0 is Block0 (`ER`); sectors 1.. each hold one
/// partition-map entry (`PM`). The first entry's `mapEntries` bounds the count.
fn extract_apm<R>(data: &[u8], budget: &mut Budget, visit: Sink<R>) -> Result<Option<R>, LimitHit> {
    // mapEntries from the first entry (sector 1), capped.
    let map_entries = be_u32(data, SECTOR + 4).min(MAX_PARTS as u32);
    let mut emitted = 0usize;
    for i in 0..map_entries as usize {
        if emitted >= MAX_PARTS {
            break;
        }
        let base = (i + 1).saturating_mul(SECTOR); // entries start at sector 1
                                                   // Each entry must begin with the `PM` signature; stop at the first miss.
        if data.get(base..base + 2) != Some(b"PM".as_slice()) {
            break;
        }
        let pblock_start = be_u32(data, base + 8) as u64;
        let pblock_count = be_u32(data, base + 12) as u64;
        if pblock_count == 0 {
            continue;
        }
        let end_sector = pblock_start.saturating_add(pblock_count);
        emitted += 1;
        let name = format!("apm-part-{emitted}");
        if let Some(r) = emit_region(data, name, pblock_start, end_sector, budget, visit)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// MBR: four 16-byte entries at offset 0x1BE. Empty (`type==0`) and protective
/// (`type==0xEE`, which defers to GPT) entries are skipped.
fn extract_mbr<R>(data: &[u8], budget: &mut Budget, visit: Sink<R>) -> Result<Option<R>, LimitHit> {
    let mut emitted = 0usize;
    for i in 0..4 {
        let e = 0x1BE + i * 16;
        let ptype = data.get(e + 4).copied().unwrap_or(0);
        if ptype == 0x00 || ptype == 0xEE {
            continue; // empty slot, or protective MBR (defer to GPT)
        }
        let lba_first = le_u32(data, e + 8) as u64;
        let sectors = le_u32(data, e + 12) as u64;
        if sectors == 0 {
            continue;
        }
        // Only carve entries whose start actually lands inside the image.
        if (lba_first as usize).saturating_mul(SECTOR) >= data.len() {
            continue;
        }
        let end_sector = lba_first.saturating_add(sectors);
        emitted += 1;
        let name = format!("mbr-part-{emitted}");
        if let Some(r) = emit_region(data, name, lba_first, end_sector, budget, visit)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
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
        // Call the extractor directly (no catch_unwind) so a genuine panic would
        // fail the test rather than being swallowed by the containment boundary.
        let run = |bytes: &[u8]| {
            let mut budget = Budget::new(Limits::default());
            let _ =
                extract_partition::<std::convert::Infallible>(bytes, &mut budget, &mut |_, _| None);
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
