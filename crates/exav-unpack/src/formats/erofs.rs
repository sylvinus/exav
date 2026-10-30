//! EROFS: the files of an image, read where they lie.
//!
//! The read-only filesystem of Android system images, container images and
//! live media. The image is a `Read + Seek`, read where the walk goes: the
//! superblock, the inodes of the directories and files, and their data. Only a
//! file is ever held, bounded by the buffer limit.
//!
//! ```text
//! superblock (1024 bytes in)   block size, where the inodes are, the root
//!   inode (32 or 64 bytes)     mode, size, how the data is laid out, and
//!                              where it is
//!   data                       whole blocks at an address, a tail after the
//!                              inode, or chunks each at an address
//!   directory                  blocks of (inode number, name) entries
//! ```
//!
//! An inode is addressed by its number: the 32-byte slot it begins at, from the
//! inode area. Data stored plain, with its tail after the inode, and in chunks
//! (with holes) is read. A file stored compressed is reported, not read, and so
//! is a file in chunks on another device. A symbolic link or a device node holds
//! no file's bytes and is not emitted. The checksum is not checked.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashSet;
use std::io::{Read, Seek};

use super::vol::{
    Attrs, Emit, Got, List, Next, Piece, Pieces, Plan, Vol, give, le16, le32, le64, read_file,
};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, LimitHit, Mtime};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// The most a directory is, bytes.
const MAX_DIR: u64 = 64 << 20;

/// How the data of an inode is laid out.
const FLAT_PLAIN: u16 = 0;
const FLAT_INLINE: u16 = 2;
const CHUNK_BASED: u16 = 4;

/// The address of a chunk that is a hole.
const NULL_ADDR: u32 = 0xFFFF_FFFF;
/// A chunk format with an index (and a device) for each chunk.
const CHUNK_INDEXES: u16 = 0x20;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

/// Whether `data`, the start of an image, holds the magic of an EROFS
/// superblock.
pub(crate) fn is_erofs(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Erofs)
}

/// What the superblock says of the image.
struct Erofs {
    /// Bytes in a block.
    bs: u64,
    /// Where the inode area begins, and the number of the root.
    meta: u64,
    root: u64,
}

/// An inode.
struct Inode {
    mode: u32,
    size: u64,
    layout: u16,
    /// The union at 16: the address of the data, or the format of the chunks.
    union: u32,
    mtime: Option<i64>,
    /// Where the data kept after it begins: past the inode and its attributes.
    after: u64,
}

impl Erofs {
    fn inode(&self, v: &mut Vol, nid: u64) -> Option<Inode> {
        let at = self.meta.checked_add(nid.checked_mul(32)?)?;
        let h = v.at(at, 32)?;
        let format = le16(&h, 0);
        // Bit 0: the longer inode. Bits 1 to 3: the layout.
        let wide = format & 1 != 0;
        let layout = (format >> 1) & 7;
        let (isize, size, mtime) = if wide {
            let ext = v.at(at.checked_add(32)?, 32)?;
            (64u64, le64(&h, 8), Some(i64::try_from(le64(&ext, 0)).ok()?))
        } else {
            (32u64, u64::from(le32(&h, 8)), None)
        };
        // The attributes: a header of 12 bytes and 4 for each count past the first.
        let icount = u64::from(le16(&h, 2));
        let xattr = if icount == 0 {
            0
        } else {
            icount
                .saturating_sub(1)
                .saturating_mul(4)
                .saturating_add(12)
        };
        let len = isize.saturating_add(xattr);
        Some(Inode {
            mode: u32::from(le16(&h, 4)),
            size,
            layout,
            union: le32(&h, 16),
            mtime,
            after: at.checked_add(len)?,
        })
    }

    /// The data of `ino`: held when it is at most `cap` bytes, else read as it
    /// goes.
    fn data<'a>(&self, v: &'a mut Vol<'_>, ino: &Inode, cap: u64) -> Got<'a> {
        if ino.size == 0 {
            return Got::Whole(Vec::new());
        }
        let size = ino.size;
        match ino.layout {
            FLAT_PLAIN | FLAT_INLINE => {
                let whole = if ino.layout == FLAT_INLINE {
                    size.checked_div(self.bs)
                        .unwrap_or(0)
                        .saturating_mul(self.bs)
                } else {
                    size
                };
                let mut pieces = Vec::new();
                // A file of less than a block has no block: no address either.
                if whole > 0 {
                    let Some(at) = u64::from(ino.union).checked_mul(self.bs) else {
                        return Got::Short(Vec::new());
                    };
                    pieces.push(Piece::Disk(at, whole));
                }
                // The tail kept after the inode.
                if whole < size {
                    pieces.push(Piece::Disk(ino.after, size.saturating_sub(whole)));
                }
                let plan = List {
                    pieces: pieces.into_iter(),
                    intact: true,
                };
                read_file(v, Pieces::new(plan, size), size, cap)
            }
            CHUNK_BASED => match self.chunks(ino) {
                Some(plan) => read_file(v, Pieces::new(plan, size), size, cap),
                None => Got::Short(Vec::new()),
            },
            _ => Got::Why("EROFS compressed file not read"),
        }
    }

    /// The chunks of a file that is in chunks, or `None` where its layout is
    /// not one.
    fn chunks(&self, ino: &Inode) -> Option<Chunks> {
        let format = (ino.union & 0xFFFF) as u16;
        let chunk = self
            .bs
            .checked_shl(u32::from(format & 0x1F))
            .filter(|&c| c > 0 && c <= 1 << 30)?;
        let unit: u64 = if format & CHUNK_INDEXES != 0 { 8 } else { 4 };
        // The map follows the attributes, at a multiple of its entries' size.
        let map = ino.after.checked_next_multiple_of(unit)?;
        Some(Chunks {
            map,
            unit,
            bs: self.bs,
            chunk,
            size: ino.size,
            count: ino.size.div_ceil(chunk),
            k: 0,
            batch: Vec::new(),
            batch_at: 0,
        })
    }

    /// The entries of directory `dir`: name and inode number. The flag is
    /// false where the directory is damaged. `left` counts the bytes of
    /// directories the walk may still read.
    fn entries(
        &self,
        v: &mut Vol,
        dir: &Inode,
        left: &mut u64,
        limit: usize,
    ) -> (Vec<(String, u64)>, bool) {
        let mut out = Vec::new();
        if dir.size > MAX_DIR || dir.size > *left {
            return (out, false);
        }
        *left = left.saturating_sub(dir.size);
        let bytes = match self.data(v, dir, MAX_DIR) {
            Got::Whole(b) => b,
            _ => return (out, false),
        };
        let bs = crate::bytes::to_usize(self.bs);
        let mut intact = true;
        for block in bytes.as_slice().chunks(bs.max(1)) {
            intact &= dirents(block, &mut out, limit);
            if out.len() >= limit {
                break;
            }
        }
        (out, intact)
    }
}

/// Append the entries of a block of a directory to `out`, up to `limit` in
/// all. False where the block is not well formed.
fn dirents(block: &[u8], out: &mut Vec<(String, u64)>, limit: usize) -> bool {
    // The first name begins where the entries end, which says how many there are.
    let first = usize::from(le16(block, 8));
    if first == 0 || !first.is_multiple_of(12) || first > block.len() {
        return false;
    }
    let count = first.checked_div(12).unwrap_or(0);
    for i in 0..count {
        let e = i.saturating_mul(12);
        let (nid, off) = (
            le64(block, e),
            usize::from(le16(block, e.saturating_add(8))),
        );
        // The name ends where the next begins, or, for the last, at its null
        // or at the end of the block.
        let end = if i.saturating_add(1) < count {
            usize::from(le16(block, e.saturating_add(20)))
        } else {
            block
                .get(off..)
                .and_then(|r| r.iter().position(|&b| b == 0))
                .map_or(block.len(), |n| off.saturating_add(n))
        };
        let Some(name) = block
            .get(off..end)
            .filter(|n| !n.is_empty() && off >= first)
        else {
            return false;
        };
        if name == b"." || name == b".." {
            continue;
        }
        if out.len() >= limit {
            return true;
        }
        out.push((String::from_utf8_lossy(name).into_owned(), nid));
    }
    true
}

/// The image's superblock, or `None` where it describes none that is read.
fn open(v: &mut Vol) -> Option<Erofs> {
    let b = v.at(1024, 128)?;
    if !is_erofs(&[&[0u8; 1024][..], &b].concat()) {
        return None;
    }
    let bits = u32::from(b[12]);
    if !(9..=16).contains(&bits) {
        return None;
    }
    let bs = 1u64.checked_shl(bits)?;
    let meta = u64::from(le32(&b, 40)).checked_mul(bs)?;
    let fs = Erofs {
        bs,
        meta,
        root: u64::from(le16(&b, 14)),
    };
    // The root is a directory.
    let root = fs.inode(v, fs.root)?;
    (root.mode & S_IFMT == S_IFDIR).then_some(fs)
}

/// How many entries of a file's chunk map are read at once.
const MAP_BATCH: u64 = 4096;

/// The stretches of a file that is in chunks, the map read as they are wanted.
struct Chunks {
    /// Where the map is, and how long its entries are.
    map: u64,
    unit: u64,
    bs: u64,
    chunk: u64,
    size: u64,
    count: u64,
    /// The next chunk.
    k: u64,
    /// Some entries of the map, from entry `batch_at`.
    batch: Vec<u8>,
    batch_at: u64,
}

impl Plan for Chunks {
    fn next(&mut self, v: &mut Vol) -> Next {
        if self.k >= self.count {
            return Next::End;
        }
        let held = (self.batch.len() as u64)
            .checked_div(self.unit)
            .unwrap_or(0);
        if self.k < self.batch_at || self.k >= self.batch_at.saturating_add(held) {
            let n = self.count.saturating_sub(self.k).min(MAP_BATCH);
            let batch = self
                .k
                .checked_mul(self.unit)
                .and_then(|o| o.checked_add(self.map))
                .and_then(|at| v.at(at, crate::bytes::to_usize(n.saturating_mul(self.unit))));
            let Some(batch) = batch else {
                return Next::Broken;
            };
            self.batch = batch;
            self.batch_at = self.k;
        }
        let entry = crate::bytes::to_usize(
            self.k
                .saturating_sub(self.batch_at)
                .saturating_mul(self.unit),
        );
        let (addr, device) = if self.unit == 8 {
            (
                le32(&self.batch, entry.saturating_add(4)),
                le16(&self.batch, entry.saturating_add(2)),
            )
        } else {
            (le32(&self.batch, entry), 0)
        };
        let want = self
            .chunk
            .min(self.size.saturating_sub(self.k.saturating_mul(self.chunk)));
        self.k = self.k.saturating_add(1);
        if addr == NULL_ADDR {
            return Next::Piece(Piece::Zeros(want));
        }
        // A chunk on another device is not on this image.
        if device != 0 {
            return Next::Broken;
        }
        match u64::from(addr).checked_mul(self.bs) {
            Some(at) => Next::Piece(Piece::Disk(at, want)),
            None => Next::Broken,
        }
    }
}

/// Walk an EROFS image given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the EROFS image `disk`, which is `len` bytes long, handing each file
/// to `visit`.
pub(crate) fn walk_volume<D: Read + Seek, R>(
    mut disk: D,
    len: u64,
    budget: &mut Budget,
    visit: Emit<R>,
) -> Result<Option<R>, LimitHit> {
    let max = crate::bytes::to_usize(budget.limits().max_buffer_bytes);
    let mut v = Vol {
        disk: &mut disk,
        len,
        max,
    };
    let head = v
        .at(0, crate::bytes::to_usize(len.min(1028)))
        .unwrap_or_default();
    if !is_erofs(&head) {
        return Ok(None);
    }
    let Some(fs) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "erofs open: the superblock or the root directory is unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    // The directories of an image are disjoint, so they are not more than it.
    let mut left = len;
    let mut damaged = false;
    let mut seen: HashSet<u64> = HashSet::from([fs.root]);
    let mut stack = vec![(fs.root, String::new(), 0usize)];
    while let Some((nid, prefix, depth)) = stack.pop() {
        let Some(dir) = fs.inode(&mut v, nid) else {
            damaged = true;
            continue;
        };
        let (list, intact) = fs.entries(&mut v, &dir, &mut left, limit);
        damaged |= !intact;
        let mut below = Vec::new();
        for (name, child) in list {
            budget.count_entry()?;
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let Some(inode) = fs.inode(&mut v, child) else {
                damaged = true;
                continue;
            };
            match inode.mode & S_IFMT {
                S_IFDIR => {
                    if depth >= MAX_DEPTH {
                        damaged = true;
                    } else if seen.insert(child) {
                        below.push((child, path, depth.saturating_add(1)));
                    }
                }
                S_IFREG => {
                    let attrs = Attrs {
                        mode: Some(inode.mode),
                        mtime: inode.mtime.map(Mtime::Unix),
                    };
                    if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                        fs.data(&mut v, &inode, cap)
                    })? {
                        return Ok(Some(r));
                    }
                }
                // A link or a node holds no file's bytes.
                _ => {}
            }
        }
        stack.extend(below.into_iter().rev());
    }
    if damaged {
        return Err(LimitHit::corrupt(
            "erofs walk: the image is damaged; the files before the damage were scanned".into(),
        ));
    }
    Ok(None)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::super::vol::collected;
    use super::*;
    use crate::Limits;
    use std::io::Cursor;

    const BS: usize = 4096;
    /// The inode area is the second block; data begins at the third.
    const META: usize = BS;
    const DATA: usize = 2 * BS;

    /// An image being written: inodes in 32-byte slots of the inode area, data
    /// in blocks after it.
    struct Img {
        d: Vec<u8>,
        slot: usize,
        blocks: usize,
    }

    impl Img {
        fn new() -> Img {
            let mut d = vec![0u8; DATA];
            d[1024..1028].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());
            d[1024 + 12] = 12;
            d[1024 + 40..1024 + 44].copy_from_slice(&1u32.to_le_bytes());
            Img {
                d,
                slot: 0,
                blocks: 2,
            }
        }

        /// Whole blocks of data; their block address.
        fn blocks(&mut self, bytes: &[u8]) -> u32 {
            let at = self.blocks;
            self.d
                .resize((at + bytes.len().div_ceil(BS).max(1)) * BS, 0);
            self.d[at * BS..at * BS + bytes.len()].copy_from_slice(bytes);
            self.blocks = self.d.len() / BS;
            at as u32
        }

        /// A compact inode of `layout`, with `tail` after it; its number.
        fn inode(&mut self, layout: u16, mode: u16, size: u32, union: u32, tail: &[u8]) -> u64 {
            let nid = self.slot;
            let at = META + nid * 32;
            let end = at + 32 + tail.len().div_ceil(32) * 32;
            if self.d.len() < end {
                self.d.resize(end.max(DATA), 0);
            }
            self.d[at..at + 2].copy_from_slice(&(layout << 1).to_le_bytes());
            self.d[at + 4..at + 6].copy_from_slice(&mode.to_le_bytes());
            self.d[at + 8..at + 12].copy_from_slice(&size.to_le_bytes());
            self.d[at + 16..at + 20].copy_from_slice(&union.to_le_bytes());
            self.d[at + 32..at + 32 + tail.len()].copy_from_slice(tail);
            self.slot += 1 + tail.len().div_ceil(32);
            nid as u64
        }

        fn file(&mut self, bytes: &[u8]) -> u64 {
            let whole = bytes.len() / BS * BS;
            let addr = if whole > 0 {
                self.blocks(&bytes[..whole])
            } else {
                0
            };
            self.inode(
                FLAT_INLINE,
                0o100644,
                bytes.len() as u32,
                addr,
                &bytes[whole..],
            )
        }

        /// A directory of `entries`, kept after its inode.
        fn dir(&mut self, entries: &[(&str, u64, u8)]) -> u64 {
            let bytes = dir_bytes(entries);
            self.inode(FLAT_INLINE, 0o040755, bytes.len() as u32, 0, &bytes)
        }

        /// The root of the image; the image.
        fn finish(mut self, root: u64) -> Vec<u8> {
            self.d[1024 + 14..1024 + 16].copy_from_slice(&(root as u16).to_le_bytes());
            self.d
        }
    }

    /// The bytes of a directory: the entries, then the names.
    fn dir_bytes(entries: &[(&str, u64, u8)]) -> Vec<u8> {
        let mut all: Vec<(&str, u64, u8)> = vec![(".", 0, 2), ("..", 0, 2)];
        all.extend_from_slice(entries);
        let mut out = Vec::new();
        let mut names = Vec::new();
        for (name, nid, ty) in &all {
            out.extend_from_slice(&nid.to_le_bytes());
            out.extend_from_slice(&((all.len() * 12 + names.len()) as u16).to_le_bytes());
            out.push(*ty);
            out.push(0);
            names.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(&names);
        out
    }

    type Member = (String, Vec<u8>, Option<&'static str>);

    fn walked(img: &[u8], limits: Limits) -> (Vec<Member>, Result<(), LimitHit>) {
        let mut out = Vec::new();
        let mut budget = Budget::new(limits);
        let len = img.len() as u64;
        let end = walk_volume(Cursor::new(img), len, &mut budget, &mut |e, _| {
            let e = e.whole();
            out.push((e.name, e.data, e.unsupported));
            None::<()>
        });
        (out, end.map(|_| ()))
    }

    fn pat(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// A root with `a` (a block and a tail), a folder `d` holding `b` (all in
    /// its tail), `h`, a file in chunks that has a hole, and an empty file.
    fn tree() -> Img {
        let mut img = Img::new();
        let a = img.file(&pat(BS + 100));
        let b = img.file(b"in d");
        let d = img.dir(&[("b", b, 1)]);
        // Two chunks of a block: the first a hole, the second at a block.
        let at = img.blocks(&pat(BS));
        let mut map = Vec::new();
        map.extend_from_slice(&NULL_ADDR.to_le_bytes());
        map.extend_from_slice(&at.to_le_bytes());
        let h = img.inode(CHUNK_BASED, 0o100644, 2 * BS as u32, 0, &map);
        let e = img.inode(FLAT_PLAIN, 0o100644, 0, 0, b"");
        let root = img.dir(&[("a", a, 1), ("d", d, 2), ("h", h, 1), ("e", e, 1)]);
        img.finish_with(root)
    }

    impl Img {
        fn finish_with(self, root: u64) -> Img {
            let d = self.finish(root);
            Img {
                d,
                slot: 0,
                blocks: 0,
            }
        }
    }

    fn sorted(mut e: Vec<Member>) -> Vec<(String, Vec<u8>)> {
        assert!(
            e.iter().all(|m| m.2.is_none()),
            "{:?}",
            e.iter().map(|m| (&m.0, m.2)).collect::<Vec<_>>()
        );
        e.sort_by(|a, b| a.0.cmp(&b.0));
        e.into_iter().map(|m| (m.0, m.1)).collect()
    }

    #[test]
    fn files_in_blocks_in_a_tail_and_in_chunks_with_a_hole_come_out() {
        let (e, end) = walked(&tree().d, Limits::default());
        end.unwrap();
        let mut hole = vec![0u8; BS];
        hole.extend(pat(BS));
        assert_eq!(
            sorted(e),
            [
                ("a".to_string(), pat(BS + 100)),
                ("d/b".to_string(), b"in d".to_vec()),
                ("e".to_string(), Vec::new()),
                ("h".to_string(), hole),
            ]
        );
    }

    #[test]
    fn a_folder_that_lists_itself_is_walked_once() {
        let mut img = Img::new();
        let b = img.file(b"in d");
        // `b` takes the slots 0 and 1, so the folder is the inode in slot 2.
        let d = img.dir(&[("b", b, 1), ("up", 2, 2)]);
        let root = img.dir(&[("d", d, 2)]);
        let img = img.finish(root);
        let (e, end) = walked(&img, Limits::default());
        end.unwrap();
        let names: Vec<_> = e.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(names, ["d/b"]);
    }

    #[test]
    fn a_file_at_an_address_past_the_image_is_reported_with_what_there_is() {
        let mut img = Img::new();
        let f = img.inode(FLAT_PLAIN, 0o100644, 100, 9999, b"");
        let root = img.dir(&[("f", f, 1)]);
        let (e, end) = walked(&img.finish(root), Limits::default());
        end.unwrap();
        assert_eq!(e[0].2, Some("file could not be read from the volume"));
    }

    #[test]
    fn a_compressed_file_is_reported_and_so_is_a_chunk_on_another_device() {
        let mut img = Img::new();
        let z = img.inode(1, 0o100644, 100, 0, b"");
        let at = img.blocks(&pat(BS));
        // An indexed chunk: advise, device 1, address.
        let mut map = vec![0u8, 0, 1, 0];
        map.extend_from_slice(&at.to_le_bytes());
        let other = img.inode(CHUNK_BASED, 0o100644, BS as u32, 0x20, &map);
        let root = img.dir(&[("z", z, 1), ("o", other, 1)]);
        let (e, end) = walked(&img.finish(root), Limits::default());
        end.unwrap();
        let by = |n: &str| e.iter().find(|m| m.0 == n).unwrap();
        assert_eq!(by("z").2, Some("EROFS compressed file not read"));
        assert_eq!(by("o").2, Some("file could not be read from the volume"));
    }

    #[test]
    fn a_block_of_a_directory_that_does_not_add_up_is_damage() {
        let good = dir_bytes(&[("x", 5, 1)]);
        let mut out = Vec::new();
        assert!(dirents(&good, &mut out, 100));
        assert_eq!(out, [("x".to_string(), 5)]);
        // No first name offset, one that is not a multiple of 12, one past the
        // block, a name that begins before the entries end.
        for edit in [(8usize, 0u16), (8, 13), (8, 4000), (20, 5)] {
            let mut bad = good.clone();
            bad[edit.0..edit.0 + 2].copy_from_slice(&edit.1.to_le_bytes());
            let mut out = Vec::new();
            assert!(!dirents(&bad, &mut out, 100), "{edit:?}");
        }
    }

    #[test]
    fn the_entry_past_the_member_limit_is_counted_and_stops_the_walk() {
        let mut img = Img::new();
        let a = img.file(b"a");
        let b = img.file(b"b");
        let c = img.file(b"c");
        let root = img.dir(&[("a", a, 1), ("b", b, 1), ("c", c, 1)]);
        let img = img.finish(root);
        let run = |max: u64| {
            let limits = Limits {
                max_members: max,
                ..Limits::default()
            };
            walked(&img, limits)
        };
        let (e, end) = run(3);
        end.unwrap();
        assert_eq!(e.len(), 3);
        let (e, end) = run(2);
        assert!(!end.unwrap_err().is_corrupt());
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn files_over_the_buffer_limit_are_read_as_they_go_in_each_layout() {
        let img = tree().d;
        let len = img.len() as u64;
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 100,
            ..Limits::default()
        });
        let (e, end) = collected(|emit| walk_volume(Cursor::new(&img[..]), len, &mut budget, emit));
        end.unwrap();
        let mut hole = vec![0u8; BS];
        hole.extend(pat(BS));
        let want = [
            ("a", pat(BS + 100), true),
            ("d/b", b"in d".to_vec(), false),
            ("e", Vec::new(), false),
            ("h", hole, true),
        ];
        for (name, data, streamed) in want {
            let (entry, was) = e.iter().find(|(m, _)| m.name == name).unwrap();
            assert_eq!(entry.data, data, "{name}");
            assert_eq!(*was, streamed, "{name}");
            assert_eq!(entry.unsupported, None, "{name}");
        }
    }

    #[test]
    fn a_chunk_map_longer_than_a_batch_is_read_in_batches() {
        // One more chunk than a batch of the map holds, each a block at the
        // same place, so the file is that block over and over.
        let n = MAP_BATCH as usize + 1;
        let mut img = Img::new();
        // The map is longer than the area of the inodes, so the data starts
        // after where it ends.
        img.blocks = 8;
        let at = img.blocks(&pat(BS));
        let map: Vec<u8> = (0..n).flat_map(|_| at.to_le_bytes()).collect();
        let f = img.inode(CHUNK_BASED, 0o100644, (n * BS) as u32, 0, &map);
        let root = img.dir(&[("f", f, 1)]);
        let img = img.finish(root);
        let len = img.len() as u64;
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 100,
            ..Limits::default()
        });
        let (e, end) = collected(|emit| walk_volume(Cursor::new(&img[..]), len, &mut budget, emit));
        end.unwrap();
        assert_eq!(e.len(), 1);
        assert!(e[0].1, "read as it goes");
        let want: Vec<u8> = (0..n).flat_map(|_| pat(BS)).collect();
        assert_eq!(e[0].0.data, want);
    }
}
