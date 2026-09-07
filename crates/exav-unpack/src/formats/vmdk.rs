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
//! The reconstructed guest disk is emitted as a single member for the partition
//! and filesystem handlers to pick up.

use std::io::Cursor;

use crate::{Budget, Entry, LimitHit, Sink};

/// `KDMV` — the sparse-extent header magic, little-endian on disk.
const SECTOR: u64 = 512;
const HEADER_LEN: usize = 512;

/// Grain-directory entry marking an unallocated range.
const GDE_UNALLOCATED: u32 = 0;

/// Marker sector kinds used by streamOptimized extents.
const MARKER_EOS: u32 = 0;
const MARKER_GT: u32 = 1;
const MARKER_GD: u32 = 2;
const MARKER_FOOTER: u32 = 3;

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

pub(crate) fn extract_vmdk<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if data.starts_with(b"# Disk DescriptorFile") {
        // The extents named here are separate files, absent from this one.
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "vmdk-disk".to_string(),
                data.len() as u64,
                false,
                "VMDK descriptor: the disk extents are separate files not in this one",
            ),
            budget,
        ));
    }
    if !super::sniff::is(data, crate::Format::Vmdk) {
        return Ok(None);
    }

    let flags = le_u32(data, 8);
    let capacity_sectors = le_u64(data, 12);
    let grain_sectors = le_u64(data, 20);
    let gd_offset = le_u64(data, 56);
    let compress_algorithm = data
        .get(77..79)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    // Bit 16 of `flags` marks compressed grains; bit 17 marks the marker-based
    // (streamOptimized) layout.
    let compressed = flags & (1 << 16) != 0 || compress_algorithm == 1;
    let virtual_size = capacity_sectors.saturating_mul(SECTOR);

    if grain_sectors == 0 || !grain_sectors.is_power_of_two() {
        return report("implausible VMDK grain size", virtual_size, budget, visit);
    }
    let grain_size = grain_sectors.saturating_mul(SECTOR) as usize;

    budget.count_entry()?;
    let cap = budget.reserve()?;
    if virtual_size > cap {
        return Ok(visit(
            Entry::unsupported(
                "vmdk-disk".to_string(),
                virtual_size,
                false,
                "VMDK disk exceeds the per-member size budget",
            ),
            budget,
        ));
    }
    let mut disk = vec![0u8; virtual_size as usize];

    // streamOptimized extents are written as a stream of marker sectors rather
    // than a navigable grain directory: each grain is preceded by its guest LBA
    // and compressed length, and the metadata markers can be skipped.
    if compressed || gd_offset == u64::MAX {
        let (wrote, undecodable) = read_markers(data, &mut disk, grain_size);
        if wrote == 0 && !disk.is_empty() {
            return Ok(visit(
                Entry::unsupported(
                    "vmdk-disk".to_string(),
                    virtual_size,
                    false,
                    "streamOptimized VMDK: no grain could be decoded",
                ),
                budget,
            ));
        }
        if undecodable > 0 {
            // Reported alongside the disk, not instead of it. A grain that fails
            // to inflate leaves zeroes behind, and zeroes that nobody mentions
            // read exactly like empty disk.
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    "vmdk-disk".to_string(),
                    (undecodable as u64).saturating_mul(grain_size as u64),
                    false,
                    "streamOptimized VMDK: grains that could not be decompressed",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
        }
        budget.commit(disk.len() as u64);
        return Ok(visit(Entry::new("vmdk-disk".to_string(), disk), budget));
    }

    // Plain sparse: grain directory -> grain tables -> grains.
    let gd_byte = gd_offset.saturating_mul(SECTOR) as usize;
    let num_gde = capacity_sectors.div_ceil(grain_sectors * 512).max(1) as usize;
    let Some(gd) = data.get(gd_byte..gd_byte + num_gde * 4) else {
        return report(
            "VMDK grain directory lies outside the image",
            virtual_size,
            budget,
            visit,
        );
    };
    for (i, gde_chunk) in gd.as_chunks::<4>().0.iter().enumerate() {
        let gde = u32::from_le_bytes(*gde_chunk);
        if gde == GDE_UNALLOCATED {
            continue;
        }
        let gt_byte = (gde as u64).saturating_mul(SECTOR) as usize;
        // A grain table is 512 entries in every published version.
        let Some(gt) = data.get(gt_byte..gt_byte + 512 * 4) else {
            continue;
        };
        for (j, gte_chunk) in gt.as_chunks::<4>().0.iter().enumerate() {
            let gte = u32::from_le_bytes(*gte_chunk);
            if gte == 0 {
                continue;
            }
            let guest = (i * 512 + j) * grain_size;
            if guest >= disk.len() {
                continue;
            }
            let n = grain_size.min(disk.len() - guest);
            let host = (gte as u64).saturating_mul(SECTOR) as usize;
            if let Some(src) = data.get(host..host + n) {
                disk[guest..guest + n].copy_from_slice(src);
            }
        }
    }
    budget.commit(disk.len() as u64);
    Ok(visit(Entry::new("vmdk-disk".to_string(), disk), budget))
}

/// Walk a streamOptimized extent's marker sectors, inflating each grain into
/// place. Returns how many grains were written, and how many were present but
/// would not inflate.
///
/// Grain data begins after the header's declared `overhead` — the sectors taken
/// by the embedded descriptor and the redundant grain tables. Starting at the
/// end of the header instead lands in the middle of that metadata and finds no
/// grains at all.
fn read_markers(data: &[u8], disk: &mut [u8], grain_size: usize) -> (usize, usize) {
    let overhead_sectors = le_u64(data, 64);
    let mut pos = (overhead_sectors.saturating_mul(SECTOR) as usize).max(HEADER_LEN);
    let mut wrote = 0usize;
    let mut undecodable = 0usize;
    while pos + 512 <= data.len() {
        // Marker: u64 LBA, u32 size, u32 type (the last only when size == 0).
        let lba = le_u64(data, pos);
        let size = le_u32(data, pos + 8) as usize;
        if size == 0 {
            let kind = le_u32(data, pos + 12);
            match kind {
                MARKER_EOS => break,
                // Metadata regions: `lba` counts the sectors that follow.
                MARKER_GT | MARKER_GD | MARKER_FOOTER => {
                    let skip = (lba as usize).saturating_mul(SECTOR as usize);
                    pos = pos.saturating_add(512).saturating_add(skip);
                    continue;
                }
                _ => {
                    pos += 512;
                    continue;
                }
            }
        }
        // A data marker: 12 bytes of header then `size` bytes of deflate,
        // padded out to a sector boundary.
        let start = pos + 12;
        let Some(raw) = data.get(start..start + size) else {
            break; // truncated stream: what precedes it has been read
        };
        let guest = (lba as usize).saturating_mul(SECTOR as usize);
        if guest < disk.len() {
            match crate::bounded_read(
                flate2::read::ZlibDecoder::new(Cursor::new(raw)),
                grain_size as u64,
            ) {
                Ok((out, _)) => {
                    let n = out.len().min(disk.len() - guest);
                    disk[guest..guest + n].copy_from_slice(&out[..n]);
                    if n > 0 {
                        wrote += 1;
                    }
                }
                // The grain's bytes are in this file; exav just could not read
                // them. That is content left unexamined, not content absent.
                Err(_) => undecodable += 1,
            }
        }
        let consumed = (12 + size).div_ceil(512) * 512;
        pos = pos.saturating_add(consumed);
    }
    (wrote, undecodable)
}

fn report<R>(
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported("vmdk-disk".to_string(), size, false, reason),
        budget,
    ))
}
