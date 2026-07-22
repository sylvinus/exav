//! UDF — the filesystem on DVDs, Blu-rays, and any `.iso` a modern tool writes.
//!
//! Windows and macOS both mount a UDF image on double-click, and 7-Zip opens
//! one, so it is as plausible a delivery container as ISO 9660 — which it has
//! largely replaced. Most `.iso` files carry **both** filesystems ("UDF bridge")
//! over the same extents, but a UDF-only image is perfectly ordinary, and there
//! the ISO 9660 walk finds nothing at all.
//!
//! Implemented from ECMA-167 and the OSTA UDF specification. All fields are
//! **little-endian**. The path from the start of the image to a file's bytes is
//! long:
//!
//! ```text
//! Anchor Volume Descriptor Pointer  (sector 256)
//!   -> Main Volume Descriptor Sequence
//!        -> Partition Descriptor   (where the partition starts)
//!        -> Logical Volume Descriptor (block size, partition maps, File Set)
//!   -> File Set Descriptor         -> root directory ICB
//!   -> File Entry                  -> allocation descriptors -> the bytes
//! ```
//!
//! Called from the ISO extractor rather than dispatched on its own, so that a
//! bridge image is walked through both filesystems with a shared set of already
//! emitted extents — the two trees name the same blocks, so files are not
//! scanned twice.

use std::collections::HashSet;

use crate::{Budget, Entry, LimitHit, Sink};

/// UDF descriptors are addressed in 2048-byte sectors regardless of the logical
/// block size the volume declares.
const SECTOR: usize = 2048;

/// The Anchor Volume Descriptor Pointer is required at sector 256; the
/// specification also allows copies at the last sector and 256 before it.
const ANCHOR_SECTOR: usize = 256;

/// Descriptor tag identifiers used here.
const TAG_ANCHOR: u16 = 2;
const TAG_PARTITION: u16 = 5;
const TAG_LOGICAL_VOLUME: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_IDENTIFIER: u16 = 257;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;

/// ICB `FileType` values that name something with bytes to scan.
const FILE_TYPE_DIRECTORY: u8 = 4;
const FILE_TYPE_FILE: u8 = 5;

/// `FileCharacteristics` bit 1: the entry is a directory; bit 3: it is the
/// parent (`..`) back-pointer.
const FID_DIRECTORY: u8 = 1 << 1;
const FID_PARENT: u8 = 1 << 3;

/// Allocation-descriptor kinds, from the low three bits of the ICB flags.
const AD_SHORT: u16 = 0;
const AD_LONG: u16 = 1;
const AD_EXTENDED: u16 = 2;
/// The file's bytes are stored inside the File Entry itself.
const AD_IN_ICB: u16 = 3;

/// Extent kinds, from the top two bits of an allocation descriptor's length.
const EXTENT_RECORDED: u32 = 0;
/// The descriptor points at a continuation of the descriptor list.
const EXTENT_CONTINUATION: u32 = 3;

/// Bounds on the walk. Both are reported when hit — a cap that stops quietly
/// leaves the rest of the image unenumerated while the file still reads clean.
const MAX_DIRS: usize = 4096;
const MAX_EXTENTS: usize = 8192;

fn le_u16(d: &[u8], off: usize) -> u16 {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

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

/// The tag identifier of the descriptor at `off`, or 0.
fn tag_at(data: &[u8], off: usize) -> u16 {
    le_u16(data, off)
}

/// Does the Volume Recognition Sequence declare a UDF filesystem? The sequence
/// starts at sector 16 and each entry is a 2048-byte descriptor whose identifier
/// sits at offset 1.
pub(crate) fn has_udf(data: &[u8]) -> bool {
    (16..32).any(|s| {
        let o = s * SECTOR + 1;
        matches!(data.get(o..o + 5), Some(b"NSR02") | Some(b"NSR03"))
    })
}

/// A UDF name is OSTA CS0: a leading byte says whether the rest is 8-bit or
/// UTF-16BE.
fn decode_name(raw: &[u8]) -> String {
    match raw.split_first() {
        Some((8, rest)) => rest.iter().map(|&c| c as char).collect(),
        Some((16, rest)) => {
            let units: Vec<u16> = rest
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        // An empty or unmarked identifier; keep whatever bytes are there rather
        // than dropping the entry.
        _ => String::from_utf8_lossy(raw).into_owned(),
    }
}

/// Where the file data lives and how it is addressed.
struct Volume {
    /// First sector of the partition the file set lives in.
    partition_start: usize,
    /// Logical block size, in bytes.
    block_size: usize,
    /// Location of the File Set Descriptor, as a logical block in the partition.
    fsd_block: u32,
}

/// Read the Anchor, the Main Volume Descriptor Sequence, and the partition it
/// names. `Err` carries a reason to report rather than a reason to stay quiet.
fn volume(data: &[u8]) -> Result<Volume, &'static str> {
    let sectors = data.len() / SECTOR;
    let anchor = [
        ANCHOR_SECTOR,
        sectors.saturating_sub(1),
        sectors.saturating_sub(257),
    ]
    .into_iter()
    .map(|s| s * SECTOR)
    .find(|&o| tag_at(data, o) == TAG_ANCHOR)
    .ok_or("UDF image has no anchor volume descriptor")?;

    // The anchor's first field is the extent holding the descriptor sequence.
    let mvds_len = le_u32(data, anchor + 16) as usize;
    let mvds_loc = le_u32(data, anchor + 20) as usize;

    let mut partition: Option<(u16, usize)> = None;
    let mut lvd: Option<usize> = None;
    for i in 0..(mvds_len / SECTOR).min(sectors) {
        let o = (mvds_loc + i) * SECTOR;
        match tag_at(data, o) {
            TAG_PARTITION => {
                partition = Some((le_u16(data, o + 22), le_u32(data, o + 188) as usize));
            }
            TAG_LOGICAL_VOLUME => lvd = Some(o),
            TAG_TERMINATING => break,
            _ => {}
        }
    }
    let (partition_number, partition_start) =
        partition.ok_or("UDF volume descriptor sequence names no partition")?;
    let lvd = lvd.ok_or("UDF volume descriptor sequence names no logical volume")?;

    let block_size = le_u32(data, lvd + 212) as usize;
    if block_size == 0 || !block_size.is_power_of_two() || block_size > 1 << 16 {
        return Err("implausible UDF logical block size");
    }
    // `LogicalVolumeContentsUse` is a long_ad naming the File Set Descriptor.
    let fsd_block = le_u32(data, lvd + 248 + 4);
    let fsd_partition_ref = le_u16(data, lvd + 248 + 12);

    // Partition maps translate a partition reference into a partition number.
    // Type 1 is the plain case; type 2 covers the virtual, sparable and metadata
    // partitions, where the blocks are indirected through a file and this direct
    // mapping would silently read the wrong bytes.
    let map_count = le_u32(data, lvd + 268) as usize;
    let mut map = lvd + 440;
    for i in 0..map_count.min(64) {
        let kind = data.get(map).copied().unwrap_or(0);
        let len = data.get(map + 1).copied().unwrap_or(0) as usize;
        if len == 0 {
            break;
        }
        if i == fsd_partition_ref as usize {
            if kind != 1 {
                return Err("UDF virtual/sparable/metadata partition map is not supported");
            }
            if le_u16(data, map + 4) != partition_number {
                return Err("UDF partition map names a partition not in this volume");
            }
            break;
        }
        map += len;
    }

    Ok(Volume {
        partition_start,
        block_size,
        fsd_block,
    })
}

impl Volume {
    /// Byte offset of a logical block within the partition.
    fn block(&self, lbn: u32) -> usize {
        self.partition_start
            .saturating_mul(SECTOR)
            .saturating_add((lbn as usize).saturating_mul(self.block_size))
    }
}

/// One allocation descriptor: where an extent is and whether its bytes were
/// actually written.
struct Extent {
    kind: u32,
    length: u32,
    block: u32,
}

/// Read a File Entry's allocation descriptors, following continuations.
/// Returns `None` when the descriptors use a form exav does not read.
fn extents(
    data: &[u8],
    vol: &Volume,
    ad_kind: u16,
    ad_area: usize,
    ad_len: usize,
) -> Option<Vec<Extent>> {
    let size = match ad_kind {
        AD_SHORT => 8,
        AD_LONG => 16,
        _ => return None,
    };
    let mut out = Vec::new();
    let (mut area, mut len) = (ad_area, ad_len);
    // Bounded because a malformed continuation can point back at itself.
    for _ in 0..MAX_EXTENTS {
        let mut consumed = 0usize;
        let mut next: Option<(usize, usize)> = None;
        while consumed + size <= len && out.len() < MAX_EXTENTS {
            let o = area + consumed;
            consumed += size;
            let raw_len = le_u32(data, o);
            let kind = raw_len >> 30;
            let length = raw_len & 0x3FFF_FFFF;
            // A short_ad's position is a block in this partition; a long_ad
            // names the partition too, but only the file set's own partition is
            // reachable here.
            let block = le_u32(data, o + 4);
            if kind == EXTENT_CONTINUATION {
                next = Some((vol.block(block), length as usize));
                break;
            }
            if length == 0 {
                continue;
            }
            out.push(Extent {
                kind,
                length,
                block,
            });
        }
        match next {
            // The continuation extent begins with its own tag; the descriptors
            // follow it.
            Some((off, l)) => {
                area = off + 24;
                len = l.saturating_sub(24);
            }
            None => break,
        }
    }
    Some(out)
}

/// A file or directory found in the tree.
struct Node {
    name: String,
    icb_block: u32,
}

pub(crate) fn extract_udf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
    seen_extents: &mut HashSet<u64>,
) -> Result<Option<R>, LimitHit> {
    let vol = match volume(data) {
        Ok(v) => v,
        Err(reason) => {
            // The image says it is UDF; failing to read its structures leaves
            // every file in it unexamined, which must not pass quietly.
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported("<udf-volume>".to_string(), 0, false, reason),
                budget,
            ));
        }
    };

    let fsd = vol.block(vol.fsd_block);
    if tag_at(data, fsd) != TAG_FILE_SET {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<udf-volume>".to_string(),
                0,
                false,
                "UDF file set descriptor is not where the volume says it is",
            ),
            budget,
        ));
    }
    // `RootDirectoryICB` is a long_ad at offset 400.
    let root = le_u32(data, fsd + 400 + 4);

    let mut queue = vec![Node {
        name: String::new(),
        icb_block: root,
    }];
    let mut walked = 0usize;
    let mut visited_icbs: HashSet<u32> = HashSet::new();

    while let Some(dir) = queue.pop() {
        walked += 1;
        if walked > MAX_DIRS {
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    format!("<udf-directories-beyond-{MAX_DIRS}>"),
                    0,
                    false,
                    "too many UDF directories to walk them all",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            break;
        }
        // A directory tree that loops back on itself would otherwise be walked
        // until the cap, hiding the rest of the image behind the budget.
        if !visited_icbs.insert(dir.icb_block) {
            continue;
        }
        let Some(body) = read_file(data, &vol, dir.icb_block, FILE_TYPE_DIRECTORY) else {
            // The directory's own extents could not be read, so everything under
            // it is invisible to this walk — not absent from the image. Skipping
            // quietly would hide a whole subtree.
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    dir.name.clone(),
                    0,
                    false,
                    "UDF directory could not be read, so its contents were not examined",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        };
        for child in read_fids(&body, &dir.name) {
            if child.is_dir {
                queue.push(Node {
                    name: child.path,
                    icb_block: child.icb_block,
                });
                continue;
            }
            let fe = vol.block(child.icb_block);
            let tag = tag_at(data, fe);
            if tag != TAG_FILE_ENTRY && tag != TAG_EXTENDED_FILE_ENTRY {
                // The entry names an ICB that is not a file entry — a strategy
                // exav does not follow. The bytes are in the image; exav just
                // cannot find them.
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        child.path,
                        0,
                        false,
                        "UDF file entry uses an ICB strategy exav does not follow",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            let ad_kind = le_u16(data, fe + 16 + 18) & 7;
            if ad_kind == AD_EXTENDED {
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        child.path,
                        le_u64(data, fe + 56),
                        false,
                        "UDF extended allocation descriptors are not read",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            // Deduplicate against the ISO 9660 walk of the same image: a bridge
            // image's two trees point at the same blocks.
            let first_block = first_extent_block(data, &vol, fe, ad_kind);
            if let Some(b) = first_block {
                if !seen_extents.insert(b) {
                    continue;
                }
            }
            let Some(content) = read_file(data, &vol, child.icb_block, FILE_TYPE_FILE) else {
                // The directory names this file, so it exists; its extents just
                // did not resolve. Report it rather than let the name vanish.
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        child.path,
                        le_u64(data, fe + 56),
                        false,
                        "UDF file content could not be read",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            };
            budget.count_entry()?;
            let cap = budget.reserve()?;
            if content.len() as u64 > cap {
                return Err(LimitHit::new(format!(
                    "udf member '{}' exceeds budget",
                    child.path
                )));
            }
            budget.commit(content.len() as u64);
            if let Some(r) = visit(Entry::new(child.path, content), budget) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

/// The **absolute sector** of a file's first recorded extent, used to recognise a
/// file the ISO 9660 walk already emitted. That walk keys on the ISO LBA, so the
/// partition-relative logical block has to be resolved to the same address space
/// or every bridged file would be emitted twice. `None` for a file stored inside
/// its own entry, which has no extent to share.
fn first_extent_block(data: &[u8], vol: &Volume, fe: usize, ad_kind: u16) -> Option<u64> {
    if ad_kind == AD_IN_ICB {
        return None;
    }
    let (ad_area, ad_len) = ad_area(data, fe);
    extents(data, vol, ad_kind, ad_area, ad_len)?
        .into_iter()
        .find(|e| e.kind == EXTENT_RECORDED)
        .map(|e| (vol.block(e.block) / SECTOR) as u64)
}

/// Where a File Entry's allocation descriptors start, and how many bytes of them
/// there are. The Extended File Entry puts the two lengths 40 bytes later.
fn ad_area(data: &[u8], fe: usize) -> (usize, usize) {
    let extended = tag_at(data, fe) == TAG_EXTENDED_FILE_ENTRY;
    let base = if extended { 208 } else { 168 };
    let ea_len = le_u32(data, fe + base) as usize;
    let ad_len = le_u32(data, fe + base + 4) as usize;
    (fe + base + 8 + ea_len, ad_len)
}

/// Read the bytes of the file or directory whose File Entry is at `icb_block`.
/// `None` when the entry is not of the expected type or cannot be read; the
/// caller has already decided whether that is worth reporting.
fn read_file(data: &[u8], vol: &Volume, icb_block: u32, want_type: u8) -> Option<Vec<u8>> {
    let fe = vol.block(icb_block);
    let tag = tag_at(data, fe);
    if tag != TAG_FILE_ENTRY && tag != TAG_EXTENDED_FILE_ENTRY {
        return None;
    }
    if data.get(fe + 16 + 11).copied()? != want_type {
        return None;
    }
    let info_len = le_u64(data, fe + 56) as usize;
    let ad_kind = le_u16(data, fe + 16 + 18) & 7;
    let (ad_area, ad_len) = ad_area(data, fe);

    if ad_kind == AD_IN_ICB {
        // The bytes sit where the descriptors would be.
        let n = ad_len.min(info_len);
        return data.get(ad_area..ad_area + n).map(<[u8]>::to_vec);
    }

    let mut out = Vec::new();
    for e in extents(data, vol, ad_kind, ad_area, ad_len)? {
        if out.len() >= info_len {
            break;
        }
        let want = (e.length as usize).min(info_len - out.len());
        if e.kind != EXTENT_RECORDED {
            // Allocated but never written: it reads as zeroes on the victim's
            // machine too, so there is nothing hidden here.
            out.resize(out.len() + want, 0);
            continue;
        }
        let start = vol.block(e.block);
        // A short read means the image is truncated: the declared bytes are
        // absent rather than hidden, and what exists is still scanned.
        match data.get(start..start + want) {
            Some(src) => out.extend_from_slice(src),
            None => break,
        }
    }
    Some(out)
}

struct Fid {
    path: String,
    icb_block: u32,
    is_dir: bool,
}

/// Walk the File Identifier Descriptors in a directory's bytes.
fn read_fids(dir: &[u8], parent: &str) -> Vec<Fid> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 38 <= dir.len() {
        if le_u16(dir, p) != TAG_FILE_IDENTIFIER {
            break;
        }
        let characteristics = dir.get(p + 18).copied().unwrap_or(0);
        let name_len = dir.get(p + 19).copied().unwrap_or(0) as usize;
        // The ICB field is a long_ad: extent length, then the location.
        let icb_block = le_u32(dir, p + 24);
        let impl_len = le_u16(dir, p + 36) as usize;
        let name_at = p + 38 + impl_len;
        let total = 38 + impl_len + name_len;

        // `..` carries no name and points back up the tree.
        if characteristics & FID_PARENT == 0 && name_len > 0 {
            if let Some(raw) = dir.get(name_at..name_at + name_len) {
                let name = decode_name(raw);
                let path = if parent.is_empty() {
                    name
                } else {
                    format!("{parent}/{name}")
                };
                out.push(Fid {
                    path,
                    icb_block,
                    is_dir: characteristics & FID_DIRECTORY != 0,
                });
            }
        }
        // Descriptors are padded to a four-byte boundary.
        let step = total.div_ceil(4) * 4;
        if step == 0 {
            break;
        }
        p += step;
    }
    out
}
