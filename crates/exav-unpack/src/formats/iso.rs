#![allow(unused_imports)]
use crate::*;
use std::collections::HashSet;
use std::io::{BufReader, Cursor, Read, Seek, Write};

const SECTOR: u64 = 2048;

/// Directory-walk guard. Hitting it is reported, never a quiet stop.
const MAX_DIRS: usize = 1024;

/// Decode a directory-record file identifier. Joliet supplementary descriptors
/// store names as UCS-2 (UTF-16) big-endian; the primary descriptor uses a
/// byte string. A trailing `;1` version suffix is stripped either way.
fn decode_name(raw: &[u8], joliet: bool) -> String {
    let name = if joliet {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_be_bytes)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    name.split(';').next().unwrap_or("").to_string()
}

/// The root directory records worth walking, as `(joliet, root_lba, root_len)`.
///
/// A malicious ISO commonly lists its payload in only ONE directory tree — often
/// the Joliet supplementary tree, leaving the primary tree empty — to hide from
/// readers that parse only the other. So we enumerate every volume descriptor
/// (they run from sector 16 until a terminator, type 255) and return the root of
/// each primary (type 1) and Joliet (type 2) tree. Joliet roots come first so
/// their long, real names win when a file appears in both trees. `read(off,len)`
/// fetches raw bytes; a short/`CD001`-less read ends enumeration.
fn vd_roots(read: &mut dyn FnMut(u64, usize) -> Vec<u8>) -> Vec<(bool, u64, u64)> {
    let mut primary = Vec::new();
    let mut joliet = Vec::new();
    for i in 0..32u64 {
        let vd = read((16 + i) * SECTOR, 190);
        if vd.len() < 190 || vd.get(1..6) != Some(b"CD001") {
            break;
        }
        let ty = vd[0];
        if ty == 255 {
            break; // volume-descriptor set terminator
        }
        if ty != 1 && ty != 2 {
            continue; // boot record or something we don't walk
        }
        let le32 = |o: usize| u32::from_le_bytes([vd[o], vd[o + 1], vd[o + 2], vd[o + 3]]) as u64;
        let root = (le32(156 + 2), le32(156 + 10));
        // A Joliet SVD carries a UCS-2 escape sequence (`%/@`, `%/C`, `%/E`) at
        // offset 88; that flags UTF-16 names. A type-2 without it is treated as a
        // plain (byte-named) tree.
        if ty == 2 && vd.get(88) == Some(&0x25) {
            joliet.push((true, root.0, root.1));
        } else {
            primary.push((false, root.0, root.1));
        }
    }
    joliet.into_iter().chain(primary).collect()
}

/// Reader-based streaming: walk the ISO 9660 directory tree(s) via targeted reads
/// (directory records are small) and return each file as `(name, offset, size)`.
/// File extents — the bulk of a disc image — stream via seek+take. Mirrors
/// [`extract_iso`]'s tree walk and emission order; `max_buffer` bounds each
/// directory read. Both the primary and Joliet trees are walked; a file present
/// in both (by extent) is emitted once.
pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
    max_buffer: u64,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let total_len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("iso: {e}")))?;
    let mut read_at = |off: u64, len: usize| -> Vec<u8> {
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
    };
    let le32 = |b: &[u8], o: usize| -> u64 {
        b.get(o..o + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()) as u64)
            .unwrap_or(0)
    };
    let roots = vd_roots(&mut read_at);
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut seen_files: HashSet<u64> = HashSet::new();
    let mut visited = 0usize;
    // Each queued dir carries the Joliet flag of the tree it belongs to.
    let mut dirs: Vec<(bool, u64, u64)> = roots;
    while let Some((joliet, lba, len)) = dirs.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            // A zero-length marker region, the same channel the partition walker
            // uses for its own caps. Breaking out silently would leave every
            // remaining directory in the image unenumerated while the file could
            // still be reported clean — and ISO is streamable, so this is the
            // path a top-level scan takes.
            out.push((format!("<iso-directories-beyond-{MAX_DIRS}>"), 0, 0));
            break;
        }
        let start = lba.saturating_mul(SECTOR);
        let avail = total_len.saturating_sub(start);
        let read_len = len.min(avail).min(max_buffer) as usize;
        let dir = read_at(start, read_len);
        let mut p = 0usize;
        while p < dir.len() {
            let rec_len = dir[p] as usize;
            if rec_len == 0 {
                let next = (p / SECTOR as usize + 1) * SECTOR as usize;
                if next <= p {
                    break;
                }
                p = next;
                continue;
            }
            if rec_len < 33 || p + rec_len > dir.len() {
                break;
            }
            let rec = &dir[p..p + rec_len];
            let child_lba = le32(rec, 2);
            let child_len = le32(rec, 10);
            let name_len = rec[32] as usize;
            let flags = rec[25];
            let is_self_or_parent = name_len == 1 && matches!(rec.get(33), Some(0) | Some(1));
            if is_self_or_parent {
                p += rec_len;
                continue;
            }
            if flags & 0x02 != 0 {
                dirs.push((joliet, child_lba, child_len));
            } else if seen_files.insert(child_lba) {
                let raw = rec.get(33..33 + name_len.min(rec_len - 33)).unwrap_or(&[]);
                let name = decode_name(raw, joliet);
                let fstart = child_lba.saturating_mul(SECTOR);
                let fend = fstart.saturating_add(child_len).min(total_len);
                if fend > fstart {
                    out.push((name, fstart, fend - fstart));
                }
            }
            p += rec_len;
        }
    }
    Ok(out)
}

/// ISO 9660: a minimal, dependency-free reader that walks the volume descriptors'
/// directory trees (primary + Joliet) and emits each file's extent. Bounded by
/// the budget and a fixed directory-count guard. A file listed in more than one
/// tree (by extent) is emitted once. Rock Ridge extensions are ignored (the raw
/// payload is what matters for scanning); Joliet is honored for both reach and
/// the real long file names.
pub(crate) fn extract_iso<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut read_at = |off: u64, len: usize| -> Vec<u8> {
        let o = off as usize;
        data.get(o..o.saturating_add(len))
            .or_else(|| data.get(o..))
            .unwrap_or(&[])
            .to_vec()
    };
    let roots = vd_roots(&mut read_at);
    if roots.is_empty() && !udf::has_udf(data) {
        return Ok(None);
    }
    let sector = SECTOR as usize;
    let mut seen_files: HashSet<u64> = HashSet::new();
    let mut dirs: Vec<(bool, u64, u64)> = roots;
    let mut visited = 0usize;
    while let Some((joliet, lba, len)) = dirs.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            // Say so. Breaking here silently would leave every remaining
            // directory in the image unenumerated while the file could still be
            // reported clean.
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    format!("<iso-directories-beyond-{MAX_DIRS}>"),
                    0,
                    false,
                    "too many ISO directories to walk them all",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            break;
        }
        let start = lba as usize * sector;
        let end = start.saturating_add(len as usize).min(data.len());
        let Some(dir) = data.get(start..end) else {
            // A directory extent lying outside the image: the image is truncated,
            // so those bytes are absent rather than hidden. Nothing to report.
            continue;
        };
        let mut p = 0usize;
        while p < dir.len() {
            let rec_len = dir[p] as usize;
            if rec_len == 0 {
                // Records don't span sector boundaries; advance to the next.
                let next = (p / sector + 1) * sector;
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
                // Corrupt record. Everything after it in this directory is
                // unreachable, so report rather than stop quietly.
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        format!("<iso-directory@lba{lba}-truncated>"),
                        0,
                        false,
                        "corrupt ISO directory record; remaining entries unreadable",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                break;
            }
            let rec = &dir[p..p + rec_len];
            let child_lba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]) as u64;
            let child_len = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]) as u64;
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
                dirs.push((joliet, child_lba, child_len));
            } else if seen_files.insert(child_lba) {
                budget.count_entry()?;
                let raw = rec.get(33..33 + name_len.min(rec_len - 33)).unwrap_or(&[]);
                let name = decode_name(raw, joliet);
                let fstart = child_lba as usize * sector;
                let fend = fstart.saturating_add(child_len as usize).min(data.len());
                // A short read means the image is truncated: the declared bytes
                // are absent from the file rather than hidden in it, so scanning
                // what exists is the honest answer. exav scans for malware, it is
                // not a file-integrity validator. See docs/QUIRKS.md.
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
    // Most `.iso` files a modern tool writes carry UDF as well, over the same
    // extents ("UDF bridge"), and a UDF-only image has no ISO 9660 tree at all.
    // `seen_files` is keyed on the extent's first block, so a file both trees
    // name is emitted once.
    if udf::has_udf(data) {
        return udf::extract_udf(data, budget, visit, &mut seen_files);
    }
    Ok(None)
}
