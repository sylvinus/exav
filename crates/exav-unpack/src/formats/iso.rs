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

/// Walk a disc image: the ISO 9660 trees, then UDF, skipping the files the
/// first already emitted (the order `extract_iso` uses). Each file is streamed
/// from where it lies.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let (members, mut seen) = stream_offsets(&mut source, budget.limits().max_buffer_bytes)?;
    if let Some(t) = crate::stream::stream_stored(&mut source, budget, visit, members)? {
        return Ok(Some(t));
    }
    crate::formats::udf::stream_udf(&mut source, budget, visit, &mut seen)
}

/// The ISO 9660 regions, and the sectors the files start at.
type StreamedTree = (Vec<Region>, HashSet<u64>);

/// Walk the ISO 9660 directory tree(s) via targeted reads (directory records
/// are small) and return each file as a region; file extents, the bulk of a
/// disc image, are streamed by the caller. `max_buffer` bounds each directory
/// read. Both the primary and Joliet trees are walked; a file present in both
/// (by extent) is emitted once. The extents emitted come back too, for the UDF
/// walk that follows to skip.
pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
    max_buffer: u64,
) -> Result<StreamedTree, LimitHit> {
    let total_len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("iso: {e}")))?;
    // `vd_roots` is shared with the in-memory walk and reads infallibly, so a
    // failure is kept here and reported after the read that hit it.
    let failed = std::cell::Cell::new(None);
    let mut read_at = |off: u64, len: usize| -> Vec<u8> {
        crate::read_at(source, off, len).unwrap_or_else(|e| {
            failed.set(Some(e));
            Vec::new()
        })
    };
    let le32 = |b: &[u8], o: usize| -> u64 {
        b.get(o..o + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()) as u64)
            .unwrap_or(0)
    };
    let roots = vd_roots(&mut read_at);
    if let Some(e) = failed.take() {
        return Err(e);
    }
    let mut out = Vec::new();
    let mut seen_files: HashSet<u64> = HashSet::new();
    if roots.is_empty() {
        return Ok((out, seen_files));
    }
    let mut visited = 0usize;
    // Each queued dir carries the Joliet flag of the tree it belongs to.
    let mut dirs: Vec<(bool, u64, u64)> = roots;
    while let Some((joliet, lba, len)) = dirs.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            // Breaking out silently would leave every remaining directory
            // unenumerated while the image could still be reported clean.
            out.push(Region::Unwalked(
                format!("<iso-directories-beyond-{MAX_DIRS}>"),
                "too many ISO directories to walk them all",
            ));
            break;
        }
        let start = lba.saturating_mul(SECTOR);
        let avail = total_len.saturating_sub(start);
        let read_len = len.min(avail).min(max_buffer) as usize;
        let dir = read_at(start, read_len);
        if let Some(e) = failed.take() {
            return Err(e);
        }
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
                // Everything after a corrupt record is unreachable.
                out.push(Region::Unwalked(
                    format!("<iso-directory@lba{lba}-truncated>"),
                    "corrupt ISO directory record; remaining entries unreadable",
                ));
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
                    out.push(Region::Member(name, fstart, fend - fstart));
                }
            }
            p += rec_len;
        }
    }
    Ok((out, seen_files))
}
