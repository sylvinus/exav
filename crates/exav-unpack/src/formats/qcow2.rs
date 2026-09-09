//! QCOW2 — QEMU's copy-on-write disk image.
//!
//! 7-Zip opens these, every hypervisor reads them, and `qemu-img convert -c`
//! produces one whose clusters are **deflate-compressed**. That last part is
//! what makes the format matter to a scanner rather than merely to a
//! virtualisation stack: a payload inside a compressed image appears nowhere in
//! the file's bytes, so nothing short of real reconstruction reaches it.
//!
//! Implemented from the public QCOW2 specification. All header and table fields
//! are **big-endian**.
//!
//! The disk is addressed through two levels of tables. A guest offset splits
//! into an L1 index, an L2 index and an offset within the cluster; `L1[i]` gives
//! the location of an L2 table, and `L2[j]` gives the location of the cluster
//! itself — or marks it unallocated (reads as zeroes) or compressed.
//!
//! Reconstruction emits the guest disk as a single member, which the partition
//! and filesystem handlers then pick up in the normal way.

use std::io::Cursor;

use crate::{Budget, Entry, LimitHit, Sink};

/// L2 entry bit 62: the cluster is deflate-compressed.
const L2_COMPRESSED: u64 = 1 << 62;
/// Mask selecting a cluster's host offset from an uncompressed L1/L2 entry.
/// Bits 9..55; the low bits are flags and the top bit is `COPIED`.
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
/// L2 entry bit 0 (qcow2 v3): the cluster reads as zeroes.
const L2_ZERO: u64 = 1;

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

pub(crate) fn is_qcow2(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Qcow2)
}

pub(crate) fn extract_qcow2<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_qcow2(data) {
        return Ok(None);
    }
    let cluster_bits = be_u32(data, 20);
    let virtual_size = be_u64(data, 24);
    let crypt_method = be_u32(data, 32);
    let l1_size = be_u32(data, 36) as usize;
    let l1_offset = be_u64(data, 40) as usize;
    let backing_file_size = be_u32(data, 16);

    // A backing file holds the clusters this image does not, and it is not in
    // this file — the same shape as a differencing VHD.
    if backing_file_size > 0 {
        return report(
            "QCOW2 with a backing file: the disk is a delta against an image not in this file",
            virtual_size,
            budget,
            visit,
        );
    }
    if crypt_method != 0 {
        return report_enc("encrypted QCOW2 image", virtual_size, budget, visit);
    }
    // 9..=21 covers the 512-byte to 2 MiB cluster sizes the format allows; the
    // shift arithmetic below is meaningless outside it.
    if !(9..=21).contains(&cluster_bits) || l1_size == 0 {
        return report("implausible QCOW2 geometry", virtual_size, budget, visit);
    }
    let cluster_size = 1usize << cluster_bits;
    let l2_entries = cluster_size / 8;

    let Some(l1) = data.get(l1_offset..l1_offset + l1_size * 8) else {
        return report(
            "QCOW2 L1 table lies outside the image",
            virtual_size,
            budget,
            visit,
        );
    };

    budget.count_entry()?;
    let cap = budget.reserve()?;
    let want = virtual_size.min((l1_size as u64) * (l2_entries as u64) * cluster_size as u64);
    if want > cap {
        return Ok(visit(
            Entry::unsupported(
                "qcow2-disk".to_string(),
                want,
                false,
                "QCOW2 disk exceeds the per-member size budget",
            ),
            budget,
        ));
    }

    // Compressed-cluster descriptor split, per the specification: the low
    // `csize_shift` bits are the host offset, the next ones the length in
    // 512-byte sectors minus one.
    let csize_shift = 62 - (cluster_bits - 8);
    let csize_mask = (1u64 << (cluster_bits - 8)) - 1;

    let mut disk = vec![0u8; want as usize];
    // A cluster whose compressed bytes are *present* but will not inflate is
    // content exav failed to read — it must be reported. A cluster pointing past
    // the end of the file is content that is not there at all, which is a
    // truncated image rather than a hidden payload, and stays quiet.
    let mut undecodable_clusters = 0usize;

    for (i, l1_chunk) in l1.as_chunks::<8>().0.iter().enumerate() {
        let l1e = u64::from_be_bytes(*l1_chunk);
        let l2_off = (l1e & OFFSET_MASK) as usize;
        if l2_off == 0 {
            continue; // no L2 table: this whole range is unallocated (zeroes)
        }
        let Some(l2) = data.get(l2_off..l2_off + l2_entries * 8) else {
            continue; // L2 table past the end: truncated image
        };
        for (j, l2_chunk) in l2.as_chunks::<8>().0.iter().enumerate() {
            let e = u64::from_be_bytes(*l2_chunk);
            let compressed = e & L2_COMPRESSED != 0;
            // Bit 0 means "reads as zeroes" for a *plain* entry only. In a
            // compressed descriptor it is part of the host offset, so testing it
            // unconditionally drops every compressed cluster that happens to
            // start at an odd byte — silently, as a hole of zeroes that scans
            // clean.
            if e == 0 || (!compressed && e & L2_ZERO != 0) {
                continue; // unallocated or explicitly zero
            }
            let guest = (i * l2_entries + j) * cluster_size;
            if guest >= disk.len() {
                continue;
            }
            let n = cluster_size.min(disk.len() - guest);

            if compressed {
                let coffset = (e & ((1u64 << csize_shift) - 1)) as usize;
                let nb_csectors = ((e >> csize_shift) & csize_mask) as usize + 1;
                // The run starts mid-sector, so the first partial sector counts
                // against the total length.
                let csize = nb_csectors * 512 - (coffset & 511);
                let Some(raw) = data.get(coffset..coffset.saturating_add(csize).min(data.len()))
                else {
                    continue; // past the end: truncated image, not a hidden cluster
                };
                // Clusters are raw DEFLATE, with no zlib wrapper.
                match crate::bounded_read(
                    flate2::read::DeflateDecoder::new(Cursor::new(raw)),
                    cluster_size as u64,
                ) {
                    Ok((out, _)) => {
                        let k = n.min(out.len());
                        disk[guest..guest + k].copy_from_slice(&out[..k]);
                    }
                    Err(_) => undecodable_clusters += 1,
                }
                continue;
            }

            // A table entry pointing past the end means the image is
            // truncated: those bytes are absent rather than hidden, so the
            // cluster stays zero.
            let host = (e & OFFSET_MASK) as usize;
            if let Some(src) = data.get(host..host + n) {
                disk[guest..guest + n].copy_from_slice(src);
            }
        }
    }

    if undecodable_clusters > 0 {
        // Reported alongside the disk, not instead of it: what was reconstructed
        // is still worth scanning, and the hole is still worth knowing about.
        // Zero-filling a failed cluster and saying nothing would hand the
        // scanner clean-looking space where real content should be.
        budget.count_entry()?;
        if let Some(r) = visit(
            Entry::unsupported(
                "qcow2-disk".to_string(),
                (undecodable_clusters as u64).saturating_mul(cluster_size as u64),
                false,
                "QCOW2 compressed clusters that could not be decompressed",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }
    budget.commit(disk.len() as u64);
    Ok(visit(Entry::new("qcow2-disk".to_string(), disk), budget))
}

fn report<R>(
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported("qcow2-disk".to_string(), size, false, reason),
        budget,
    ))
}

fn report_enc<R>(
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    Ok(visit(
        Entry::unsupported("qcow2-disk".to_string(), size, true, reason),
        budget,
    ))
}
