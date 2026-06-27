#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// ISO 9660: a minimal, dependency-free reader that walks the primary volume
/// descriptor's directory tree and emits each file's extent. Bounded by the
/// budget and a fixed directory-recursion depth. Rock Ridge / Joliet name
/// extensions are ignored (the raw payload is what matters for scanning).
pub(crate) fn extract_iso<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    const SECTOR: usize = 2048;
    // Primary Volume Descriptor at sector 16; root directory record at PVD+156.
    let pvd = 16 * SECTOR;
    let rd = pvd + 156;
    if data.len() < rd + 34 || data.get(pvd + 1..pvd + 6) != Some(b"CD001") {
        return Ok(None);
    }
    let le32 = |o: usize| -> u64 {
        u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) as u64
    };
    // (extent_lba, data_len) of directories still to visit.
    let mut dirs = vec![(le32(rd + 2), le32(rd + 10))];
    let mut visited = 0usize;
    while let Some((lba, len)) = dirs.pop() {
        visited += 1;
        if visited > 1024 {
            break; // directory-count guard
        }
        let start = lba as usize * SECTOR;
        let end = start.saturating_add(len as usize).min(data.len());
        let Some(dir) = data.get(start..end) else {
            continue;
        };
        let mut p = 0usize;
        while p < dir.len() {
            let rec_len = dir[p] as usize;
            if rec_len == 0 {
                // Records don't span sector boundaries; advance to the next.
                let next = (p / SECTOR + 1) * SECTOR;
                if next <= p {
                    break;
                }
                p = next;
                continue;
            }
            // `rec_len` is the record's own declared length; it must cover the
            // 33-byte fixed area we index below. A short (but non-zero) length is
            // corrupt — bail rather than slice `rec` too short and panic.
            if rec_len < 33 || p + rec_len > dir.len() {
                break;
            }
            let rec = &dir[p..p + rec_len];
            let child_lba =
                u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]) as u64;
            let child_len =
                u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]) as u64;
            let name_len = rec[32] as usize;
            let flags = rec[25];
            // First two records are "." and ".." (name_len 1, names 0x00/0x01).
            let is_self_or_parent = name_len == 1 && matches!(rec.get(33), Some(0) | Some(1));
            if is_self_or_parent {
                p += rec_len;
                continue;
            }
            if flags & 0x02 != 0 {
                // Subdirectory: queue it (depth bounded by the count guard).
                dirs.push((child_lba, child_len));
            } else {
                budget.count_entry()?;
                // Strip a trailing ";1" version suffix from the name.
                let raw = rec.get(33..33 + name_len.min(rec_len - 33)).unwrap_or(&[]);
                let name = String::from_utf8_lossy(raw)
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let fstart = child_lba as usize * SECTOR;
                let fend = fstart
                    .saturating_add(child_len as usize)
                    .min(data.len());
                let content = data.get(fstart..fend).unwrap_or(&[]);
                let cap = budget.reserve()?;
                if content.len() as u64 > cap {
                    return Err(LimitHit::new(format!("iso member '{name}' exceeds budget")));
                }
                budget.commit(content.len() as u64);
                if let Some(r) = visit(Entry::new(name, content.to_vec()), budget) {
                    return Ok(Some(r));
                }
            }
            p += rec_len;
        }
    }
    Ok(None)
}
