//! ext2, ext3 and ext4: the files of a volume, read where they lie.
//!
//! A disk image handed to a victim is mounted, and what they run is a file in
//! the filesystem. Carving finds a file whose magic sits at the start of a
//! contiguous run and misses the rest, and ext4 fragments freely: a file
//! written into a hole left by a deleted one lands in two extents, and the
//! first fragment alone will not decompress. Reassembling it takes the inode's
//! extent tree or block map, which means reading the filesystem.
//!
//! The volume is a `Read + Seek`, read where the walk goes: the superblock, the
//! group descriptors, each directory's blocks, the inodes it names and the
//! files' blocks. Only a file is ever held, bounded by the buffer limit.
//!
//! ```text
//! superblock (1024 bytes in)   block size, inode size, group geometry
//!   group descriptors          where each group's inode table is
//!     inode table              mode, size, and 60 bytes that are an extent
//!                              tree root, a block map, or the data itself
//!   directories                linear lists of (inode, name); an indexed
//!                              directory is read as the list it also is
//! ```
//!
//! Extents (ext4), block maps (ext2/3), inline data, 64-bit group descriptors
//! and meta block groups are followed. A preallocated extent reads as zeros, as
//! it does to the system that mounts the volume. A file in an encrypted
//! directory is reported. A symbolic link or a device node holds no file's
//! bytes and is not emitted. The journal is not replayed, and no checksum is
//! checked: a structure the system would refuse to mount is read all the same,
//! which can only show a scan more.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};

use super::vol::{Attrs, Emit, Got, Next, Piece, Pieces, Plan, Vol, give, le16, le32, read_file};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, LimitHit, Mtime};

/// The inode of the root directory.
const ROOT: u32 = 2;

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// The most runs of blocks one file or directory is followed through.
const MAX_RUNS: usize = 1 << 20;

/// The most blocks of an extent tree or block map one file is followed through.
const MAX_TREE_NODES: u32 = 1 << 16;

/// The deepest an extent tree goes.
const MAX_EXTENT_DEPTH: u16 = 5;

/// How many descriptor blocks are kept.
const DESC_CACHE: usize = 64;

/// `s_feature_incompat` bits.
const INCOMPAT_JOURNAL_DEV: u32 = 0x8;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
/// `s_feature_compat` and `s_feature_ro_compat` bits.
const COMPAT_SPARSE_SUPER2: u32 = 0x200;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
const RO_COMPAT_BIGALLOC: u32 = 0x200;

/// `i_flags` bits.
const ENCRYPT_FL: u32 = 0x800;
const EXTENTS_FL: u32 = 0x8_0000;
const INLINE_DATA_FL: u32 = 0x1000_0000;

const S_IFMT: u16 = 0o170000;
const S_IFREG: u16 = 0o100000;
const S_IFDIR: u16 = 0o040000;

/// Whether `data`, the start of a volume, holds an ext superblock's magic.
pub(crate) fn is_ext(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Ext)
}

/// What the superblock says of the volume.
struct Fs {
    /// Bytes in a block.
    bs: u64,
    /// Blocks in the volume: those it says it has, or fewer where the image
    /// ends first.
    blocks: u64,
    first_data: u64,
    /// Blocks and inodes in a group.
    bpg: u64,
    ipg: u64,
    inodes: u64,
    inode_size: usize,
    desc_size: usize,
    groups: u64,
    meta_bg: bool,
    first_meta_bg: u64,
    sparse: bool,
    sparse2: bool,
    backup: [u64; 2],
    large_dir: bool,
    /// Descriptor blocks read, by block.
    descs: HashMap<u64, Vec<u8>>,
}

/// An inode.
struct Inode {
    mode: u16,
    flags: u32,
    size: u64,
    mtime: i64,
    raw: Vec<u8>,
}

impl Inode {
    fn kind(&self) -> u16 {
        self.mode & S_IFMT
    }

    /// The 60 bytes that hold the extent tree, the block map or the data.
    fn block(&self) -> &[u8] {
        crate::bytes::at(&self.raw, 40, 60).unwrap_or(&[])
    }

    fn attrs(&self) -> Attrs {
        Attrs {
            mode: Some(u32::from(self.mode)),
            mtime: Some(Mtime::Unix(self.mtime)),
        }
    }
}

/// A run of a file's blocks.
struct Run {
    logical: u64,
    phys: u64,
    len: u64,
    /// Preallocated, not written: it reads as zeros.
    zero: bool,
}

/// The stretches of a file, from its runs: a block the map does not give is a
/// hole.
struct Extents {
    runs: std::vec::IntoIter<Run>,
    /// A run held back while the hole before it is given.
    pending: Option<Run>,
    bs: u64,
    size: u64,
    /// How many bytes of the file the stretches given so far cover.
    at: u64,
    /// The map is whole where its runs end.
    intact: bool,
}

impl Plan for Extents {
    fn next(&mut self, _: &mut Vol) -> Next {
        loop {
            if self.at >= self.size {
                return Next::End;
            }
            let Some(run) = self.pending.take().or_else(|| self.runs.next()) else {
                // Past the last run, to the end of the file, is a hole.
                if !self.intact {
                    return Next::Broken;
                }
                let n = self.size.saturating_sub(self.at);
                self.at = self.size;
                return Next::Piece(Piece::Zeros(n));
            };
            let from = run.logical.saturating_mul(self.bs);
            if from >= self.size {
                self.runs = Vec::new().into_iter();
                continue;
            }
            // Runs come in order and do not overlap.
            if from < self.at {
                return Next::Broken;
            }
            if from > self.at {
                let hole = from.saturating_sub(self.at);
                self.at = from;
                self.pending = Some(run);
                return Next::Piece(Piece::Zeros(hole));
            }
            let want = run
                .len
                .saturating_mul(self.bs)
                .min(self.size.saturating_sub(from));
            self.at = from.saturating_add(want);
            if run.zero {
                return Next::Piece(Piece::Zeros(want));
            }
            return match run.phys.checked_mul(self.bs) {
                Some(at) => Next::Piece(Piece::Disk(at, want)),
                None => Next::Broken,
            };
        }
    }
}

/// Where following a map stands.
enum Flow {
    More,
    /// Everything wanted has been seen.
    Done,
    Bad,
}

impl Fs {
    /// Whether group `g` holds a copy of the superblock.
    fn has_super(&self, g: u64) -> bool {
        if g == 0 {
            return true;
        }
        if self.sparse2 {
            return g == self.backup[0] || g == self.backup[1];
        }
        if !self.sparse {
            return true;
        }
        g == 1 || [3u64, 5, 7].iter().any(|&p| is_power_of(g, p))
    }

    /// The block of group `g`'s inode table.
    fn inode_table(&mut self, v: &mut Vol, g: u64) -> Option<u64> {
        if g >= self.groups {
            return None;
        }
        let per = self.bs.checked_div(self.desc_size as u64)?;
        let (nr, idx) = (g.checked_div(per)?, g.checked_rem(per)?);
        let at = if !self.meta_bg || nr < self.first_meta_bg {
            // The superblock is in block 1 of a volume of 1 KiB blocks, else in 0.
            let sb = u64::from(self.bs == 1024);
            sb.saturating_add(1).saturating_add(nr)
        } else {
            let first = nr.saturating_mul(per);
            self.first_data
                .saturating_add(first.saturating_mul(self.bpg))
                .saturating_add(u64::from(self.has_super(first)))
        };
        if !self.descs.contains_key(&at) {
            let block = v.at(at.checked_mul(self.bs)?, crate::bytes::to_usize(self.bs))?;
            if self.descs.len() >= DESC_CACHE {
                self.descs.clear();
            }
            self.descs.insert(at, block);
        }
        let block = self.descs.get(&at)?;
        let d = crate::bytes::at(
            block,
            crate::bytes::to_usize(idx).checked_mul(self.desc_size)?,
            self.desc_size,
        )?;
        let lo = u64::from(le32(d, 8));
        let hi = if self.desc_size >= 64 {
            u64::from(le32(d, 0x28))
        } else {
            0
        };
        Some(lo | hi.checked_shl(32)?)
    }

    fn inode(&mut self, v: &mut Vol, ino: u32) -> Option<Inode> {
        let n = u64::from(ino);
        if n == 0 || n > self.inodes {
            return None;
        }
        let n = n.saturating_sub(1);
        let table = self.inode_table(v, n.checked_div(self.ipg)?)?;
        let slot = n.checked_rem(self.ipg)?;
        let off = table
            .checked_mul(self.bs)?
            .checked_add(slot.checked_mul(self.inode_size as u64)?)?;
        let raw = v.at(off, self.inode_size)?;
        let mode = le16(&raw, 0);
        let kind = mode & S_IFMT;
        let hi = if kind == S_IFREG || (kind == S_IFDIR && self.large_dir) {
            u64::from(le32(&raw, 108))
        } else {
            0
        };
        let size = u64::from(le32(&raw, 4)) | hi.checked_shl(32)?;
        // The high bits of the time are in the extra fields, if the inode has them.
        let extra = usize::from(le16(&raw, 128)) >= 12;
        let epoch = if extra { le32(&raw, 136) & 3 } else { 0 };
        let secs = i64::from(i32::from_le_bytes(le32(&raw, 16).to_le_bytes()));
        let mtime = secs.saturating_add(i64::from(epoch).saturating_mul(1 << 32));
        Some(Inode {
            mode,
            flags: le32(&raw, 32),
            size,
            mtime,
            raw,
        })
    }

    /// The runs of `ino`'s blocks before logical block `upto`, in order. The
    /// flag is false where the extent tree or the block map is damaged.
    fn runs(&self, v: &mut Vol, ino: &Inode, upto: u64) -> (Vec<Run>, bool) {
        let mut m = Map {
            fs: self,
            upto,
            runs: Vec::new(),
            next: 0,
            nodes: 0,
        };
        let flow = if ino.flags & EXTENTS_FL != 0 {
            m.extents(v, ino.block(), None)
        } else {
            m.blocks(v, ino.block())
        };
        (m.runs, !matches!(flow, Flow::Bad))
    }

    /// The bytes of a regular file: held when they are at most `cap`, else
    /// read as they go.
    fn file<'a>(&self, v: &'a mut Vol<'_>, ino: &Inode, cap: u64) -> Got<'a> {
        if ino.flags & ENCRYPT_FL != 0 {
            return Got::Locked("ext file is encrypted");
        }
        if ino.flags & INLINE_DATA_FL != 0 {
            let size = crate::bytes::to_usize(ino.size);
            let mut data = inline_data(ino);
            let whole = data.len() >= size;
            data.truncate(size);
            return if whole {
                Got::Whole(data)
            } else {
                Got::Short(data)
            };
        }
        let (runs, intact) = self.runs(v, ino, ino.size.div_ceil(self.bs));
        let plan = Extents {
            runs: runs.into_iter(),
            pending: None,
            bs: self.bs,
            size: ino.size,
            at: 0,
            intact,
        };
        read_file(v, Pieces::new(plan, ino.size), ino.size, cap)
    }

    /// The entries of directory `ino`, up to `limit` of them. The flag is
    /// false where the directory is damaged. `left` counts the directory blocks
    /// the walk may still read.
    fn entries(
        &self,
        v: &mut Vol,
        ino: &Inode,
        left: &mut u64,
        limit: usize,
    ) -> (Vec<(String, u32)>, bool) {
        let mut out = Vec::new();
        let bs = crate::bytes::to_usize(self.bs);
        if ino.flags & INLINE_DATA_FL != 0 {
            // The parent's number, then entries; more of them in the attribute.
            let head = ino.block().get(4..).unwrap_or(&[]);
            let mut intact = dirents(head, bs, &mut out, limit);
            if let Some(more) = system_data(&ino.raw) {
                intact &= dirents(more, bs, &mut out, limit);
            }
            return (out, intact);
        }
        let upto = ino.size.div_ceil(self.bs);
        let (runs, mut intact) = self.runs(v, ino, upto);
        let mut at = 0u64;
        'runs: for run in runs {
            // A directory with a hole in it.
            intact &= run.logical == at;
            at = run.logical;
            for i in 0..run.len.min(upto.saturating_sub(run.logical)) {
                if *left == 0 {
                    intact = false;
                    break 'runs;
                }
                *left = left.saturating_sub(1);
                at = at.saturating_add(1);
                // A block never written is zeros, which is no entry.
                let block = (!run.zero)
                    .then(|| {
                        let blk = run.phys.saturating_add(i);
                        blk.checked_mul(self.bs).and_then(|o| v.at(o, bs))
                    })
                    .flatten();
                let Some(block) = block else {
                    intact = false;
                    continue;
                };
                intact &= dirents(&block, bs, &mut out, limit);
                if out.len() >= limit {
                    break 'runs;
                }
            }
        }
        (out, intact)
    }
}

/// Whether `n` is a power of `p`.
fn is_power_of(mut n: u64, p: u64) -> bool {
    if n == 0 || p < 2 {
        return false;
    }
    while n.checked_rem(p) == Some(0) {
        n = n.checked_div(p).unwrap_or(0);
    }
    n == 1
}

/// The length of a directory entry, as the block size stores it.
fn rec_len(raw: u16, bs: usize) -> usize {
    if bs < 1 << 16 {
        usize::from(raw)
    } else if raw == 0 || raw == u16::MAX {
        bs
    } else {
        usize::from(raw & 0xFFFC) | (usize::from(raw & 3) << 16)
    }
}

/// Append the named entries of a block of directory entries to `out`, up to
/// `limit` in all. False where an entry is not well formed: the rest of the
/// block is not read.
fn dirents(block: &[u8], bs: usize, out: &mut Vec<(String, u32)>, limit: usize) -> bool {
    let mut pos = 0usize;
    while pos < block.len() {
        let Some(head) = crate::bytes::at(block, pos, 8) else {
            return false;
        };
        let ino = le32(head, 0);
        let rec = rec_len(le16(head, 4), bs);
        let name_len = usize::from(head[6]);
        let end = pos.saturating_add(rec);
        if rec < 8
            || !rec.is_multiple_of(4)
            || end > block.len()
            || name_len.saturating_add(8) > rec
        {
            return false;
        }
        let name = crate::bytes::at(block, pos.saturating_add(8), name_len).unwrap_or(&[]);
        // The directory and its parent are not entries of it to walk.
        if ino != 0 && name_len > 0 && name != b"." && name != b".." {
            if out.len() >= limit {
                return true;
            }
            out.push((String::from_utf8_lossy(name).into_owned(), ino));
        }
        pos = end;
    }
    true
}

/// The `system.data` attribute kept in the inode itself: the end of a file or
/// a directory that does not fit the 60 bytes of `i_block`.
fn system_data(raw: &[u8]) -> Option<&[u8]> {
    let start = 128usize.saturating_add(usize::from(le16(raw, 128)));
    let region = raw.get(start..)?;
    if le32(region, 0) != 0xEA02_0000 {
        return None;
    }
    let mut pos = 4usize;
    loop {
        let e = crate::bytes::at(region, pos, 16)?;
        if le32(e, 0) == 0 {
            return None;
        }
        let name_len = usize::from(e[0]);
        let name = crate::bytes::at(region, pos.saturating_add(16), name_len)?;
        if e[1] == 7 && name == b"data" {
            // Values are placed from the first entry on.
            let off = 4usize.saturating_add(usize::from(le16(e, 2)));
            return crate::bytes::at(region, off, crate::bytes::to_usize(u64::from(le32(e, 8))));
        }
        let step = name_len.saturating_add(16).saturating_add(3) & !3;
        pos = pos.saturating_add(step);
    }
}

/// The bytes of a file or a directory kept in its inode.
fn inline_data(ino: &Inode) -> Vec<u8> {
    let mut data = ino.block().to_vec();
    if let Some(more) = system_data(&ino.raw) {
        data.extend_from_slice(more);
    }
    data
}

/// Following the extent tree or the block map of one inode.
struct Map<'a> {
    fs: &'a Fs,
    /// The first logical block that is not wanted.
    upto: u64,
    runs: Vec<Run>,
    /// The logical block the next run must not start before.
    next: u64,
    nodes: u32,
}

impl Map<'_> {
    fn push(&mut self, run: Run) -> Flow {
        if run.logical >= self.upto {
            return Flow::Done;
        }
        // Runs come in order and do not overlap; one that does is not a map.
        if run.logical < self.next || self.runs.len() >= MAX_RUNS {
            return Flow::Bad;
        }
        self.next = run.logical.saturating_add(run.len);
        self.runs.push(run);
        Flow::More
    }

    /// The runs of the extent tree whose node is `node`.
    fn extents(&mut self, v: &mut Vol, node: &[u8], depth: Option<u16>) -> Flow {
        let height = le16(node, 6);
        let entries = usize::from(le16(node, 2));
        let room = node.len().saturating_sub(12).checked_div(12).unwrap_or(0);
        if le16(node, 0) != 0xF30A
            || height > MAX_EXTENT_DEPTH
            || depth.is_some_and(|d| d != height)
            || entries > room
        {
            return Flow::Bad;
        }
        for i in 0..entries {
            let at = 12usize.saturating_add(i.saturating_mul(12));
            let Some(e) = crate::bytes::at(node, at, 12) else {
                return Flow::Bad;
            };
            let block = u64::from(le32(e, 0));
            if height == 0 {
                let raw = u64::from(le16(e, 4));
                // A length past 32768 marks an extent preallocated, not written.
                let (len, zero) = match raw.checked_sub(32768) {
                    Some(n) if n > 0 => (n, true),
                    _ => (raw, false),
                };
                if len == 0 {
                    continue;
                }
                let phys = u64::from(le32(e, 8)) | u64::from(le16(e, 6)).saturating_mul(1 << 32);
                match self.push(Run {
                    logical: block,
                    phys,
                    len,
                    zero,
                }) {
                    Flow::More => {}
                    other => return other,
                }
            } else {
                if block >= self.upto {
                    return Flow::Done;
                }
                let child = u64::from(le32(e, 4)) | u64::from(le16(e, 8)).saturating_mul(1 << 32);
                self.nodes = self.nodes.saturating_add(1);
                let read = (self.nodes <= MAX_TREE_NODES)
                    .then(|| child.checked_mul(self.fs.bs))
                    .flatten()
                    .and_then(|o| v.at(o, crate::bytes::to_usize(self.fs.bs)));
                let Some(read) = read else {
                    return Flow::Bad;
                };
                match self.extents(v, &read, Some(height.saturating_sub(1))) {
                    Flow::More => {}
                    other => return other,
                }
            }
        }
        Flow::More
    }

    /// The runs of a block map, `i_block` being twelve block numbers and then
    /// those of a block of block numbers, one of those, and one of those.
    fn blocks(&mut self, v: &mut Vol, i_block: &[u8]) -> Flow {
        let mut at = 0u64;
        let mut last: Option<Run> = None;
        let flow = self.map_blocks(v, i_block, &mut at, &mut last);
        if let Some(run) = last
            && let Flow::Bad = self.push(run)
        {
            return Flow::Bad;
        }
        flow
    }

    fn map_blocks(
        &mut self,
        v: &mut Vol,
        i_block: &[u8],
        at: &mut u64,
        last: &mut Option<Run>,
    ) -> Flow {
        for slot in 0..15usize {
            if *at >= self.upto {
                return Flow::Done;
            }
            let ptr = u64::from(le32(i_block, slot.saturating_mul(4)));
            let level = match slot {
                0..=11 => 0u32,
                12 => 1,
                13 => 2,
                _ => 3,
            };
            match self.level(v, level, ptr, at, last) {
                Flow::More => {}
                other => return other,
            }
        }
        Flow::More
    }

    /// The blocks `ptr` stands for: a data block at level 0, else a block of
    /// pointers to the level below.
    fn level(
        &mut self,
        v: &mut Vol,
        level: u32,
        ptr: u64,
        at: &mut u64,
        last: &mut Option<Run>,
    ) -> Flow {
        let per = self.fs.bs.checked_div(4).unwrap_or(0);
        if level == 0 {
            let here = *at;
            *at = at.saturating_add(1);
            if ptr == 0 {
                return self.flush(last);
            }
            if let Some(run) = last
                && run.phys.saturating_add(run.len) == ptr
                && run.logical.saturating_add(run.len) == here
            {
                run.len = run.len.saturating_add(1);
                return Flow::More;
            }
            if let Flow::Bad = self.flush(last) {
                return Flow::Bad;
            }
            *last = Some(Run {
                logical: here,
                phys: ptr,
                len: 1,
                zero: false,
            });
            return Flow::More;
        }
        if ptr == 0 {
            // A hole as wide as the blocks below it.
            *at = at.saturating_add(per.saturating_pow(level));
            return self.flush(last);
        }
        self.nodes = self.nodes.saturating_add(1);
        let read = (self.nodes <= MAX_TREE_NODES)
            .then(|| ptr.checked_mul(self.fs.bs))
            .flatten()
            .and_then(|o| v.at(o, crate::bytes::to_usize(self.fs.bs)));
        let Some(read) = read else {
            return Flow::Bad;
        };
        for i in 0..crate::bytes::to_usize(per) {
            if *at >= self.upto {
                return Flow::Done;
            }
            let p = u64::from(le32(&read, i.saturating_mul(4)));
            match self.level(v, level.saturating_sub(1), p, at, last) {
                Flow::More => {}
                other => return other,
            }
        }
        Flow::More
    }

    fn flush(&mut self, last: &mut Option<Run>) -> Flow {
        match last.take() {
            Some(run) => self.push(run),
            None => Flow::More,
        }
    }
}

/// The volume's superblock, or `None` where it is not one a system would mount.
fn open(v: &mut Vol) -> Option<Fs> {
    let sb = v.at(1024, 1024)?;
    if le16(&sb, 56) != 0xEF53 {
        return None;
    }
    let bs = 1024u64
        .checked_shl(le32(&sb, 24))
        .filter(|&b| b <= 1 << 16)?;
    let (compat, incompat, ro_compat) = (le32(&sb, 92), le32(&sb, 96), le32(&sb, 100));
    // A journal kept apart from the files it journals holds none of them.
    if incompat & INCOMPAT_JOURNAL_DEV != 0 {
        return None;
    }
    let wide = incompat & INCOMPAT_64BIT != 0;
    let hi = if wide { u64::from(le32(&sb, 336)) } else { 0 };
    let blocks = (u64::from(le32(&sb, 4)) | hi.checked_shl(32)?).min(v.len.checked_div(bs)?);
    let first_data = u64::from(le32(&sb, 20));
    let (bpg, ipg) = (u64::from(le32(&sb, 32)), u64::from(le32(&sb, 40)));
    // A bitmap bit stands for a cluster, which is a block unless bigalloc says more.
    let ratio = if ro_compat & RO_COMPAT_BIGALLOC != 0 {
        let shift = le32(&sb, 28).checked_sub(le32(&sb, 24))?;
        1u64.checked_shl(shift).filter(|&r| r <= 1 << 16)?
    } else {
        1
    };
    let per_bitmap = bs.checked_mul(8)?;
    if bpg == 0
        || ipg == 0
        || bpg > per_bitmap.checked_mul(ratio)?
        || ipg > per_bitmap
        || blocks <= first_data
    {
        return None;
    }
    let inode_size = if le32(&sb, 76) == 0 {
        128
    } else {
        usize::from(le16(&sb, 88))
    };
    if !inode_size.is_power_of_two() || inode_size < 128 || inode_size as u64 > bs {
        return None;
    }
    let desc_size = if wide {
        usize::from(le16(&sb, 254))
    } else {
        32
    };
    if !desc_size.is_power_of_two() || desc_size < 32 || (wide && desc_size < 64) {
        return None;
    }
    if desc_size as u64 > bs {
        return None;
    }
    let groups = blocks.saturating_sub(first_data).div_ceil(bpg);
    let mut fs = Fs {
        bs,
        blocks,
        first_data,
        bpg,
        ipg,
        inodes: u64::from(le32(&sb, 0)).min(groups.saturating_mul(ipg)),
        inode_size,
        desc_size,
        groups,
        meta_bg: incompat & INCOMPAT_META_BG != 0,
        first_meta_bg: u64::from(le32(&sb, 0x104)),
        sparse: ro_compat & RO_COMPAT_SPARSE_SUPER != 0,
        sparse2: compat & COMPAT_SPARSE_SUPER2 != 0,
        backup: [u64::from(le32(&sb, 0x24C)), u64::from(le32(&sb, 0x250))],
        large_dir: incompat & INCOMPAT_LARGEDIR != 0,
        descs: HashMap::new(),
    };
    // A volume whose root is not a directory is none that can be walked.
    let root = fs.inode(v, ROOT)?;
    (root.kind() == S_IFDIR).then_some(fs)
}

/// Whether `src` is an ext volume a system would mount: a superblock, and a root
/// that is a directory. The first kilobyte is left to boot code, so a file that
/// starts as something else can be one too.
pub(crate) fn is_volume(src: &dyn ByteSource) -> bool {
    let mut disk = Reader::new(src);
    let mut v = Vol {
        disk: &mut disk,
        len: src.len() as u64,
        max: 1 << 20,
    };
    v.at(1080, 2).is_some_and(|m| m == [0x53, 0xEF]) && open(&mut v).is_some()
}

/// Walk an ext volume given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the ext volume `disk`, which is `len` bytes long, handing each file to
/// `visit`.
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
    match v.at(1080, 2) {
        Some(magic) if magic == [0x53, 0xEF] => {}
        _ => return Ok(None),
    }
    let Some(mut fs) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "ext open: the superblock or the root directory is unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    let mut left = fs.blocks;
    let mut damaged = false;
    // A directory is walked once, whatever names it has.
    let mut seen: HashSet<u32> = HashSet::from([ROOT]);
    let mut stack = vec![(ROOT, String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        let Some(ino) = fs.inode(&mut v, dir) else {
            damaged = true;
            continue;
        };
        let (list, intact) = fs.entries(&mut v, &ino, &mut left, limit);
        damaged |= !intact;
        let mut below = Vec::new();
        for (name, n) in list {
            budget.count_entry()?;
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let Some(child) = fs.inode(&mut v, n) else {
                damaged = true;
                continue;
            };
            match child.kind() {
                S_IFDIR => {
                    if depth >= MAX_DEPTH {
                        damaged = true;
                    } else if seen.insert(n) {
                        below.push((n, path, depth.saturating_add(1)));
                    }
                }
                S_IFREG => {
                    let attrs = child.attrs();
                    if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                        fs.file(&mut v, &child, cap)
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
            "ext walk: the volume is damaged; the files before the damage were scanned".into(),
        ));
    }
    Ok(None)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fs(bs: u64) -> Fs {
        Fs {
            bs,
            blocks: 1 << 20,
            first_data: 0,
            bpg: 8192,
            ipg: 8192,
            inodes: 1 << 20,
            inode_size: 256,
            desc_size: 64,
            groups: 1,
            meta_bg: false,
            first_meta_bg: 0,
            sparse: true,
            sparse2: false,
            backup: [0; 2],
            large_dir: false,
            descs: HashMap::new(),
        }
    }

    /// An extent node: the header, then `entries` as (first, len, physical) of
    /// a leaf, or (first, 0, child) of an index when `height` is not 0.
    fn node(height: u16, entries: &[(u32, u16, u32)]) -> Vec<u8> {
        let mut n = vec![0u8; 12 + 12 * entries.len()];
        n[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
        n[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        n[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        n[6..8].copy_from_slice(&height.to_le_bytes());
        for (i, (first, len, phys)) in entries.iter().enumerate() {
            let e = 12 + 12 * i;
            n[e..e + 4].copy_from_slice(&first.to_le_bytes());
            if height == 0 {
                n[e + 4..e + 6].copy_from_slice(&len.to_le_bytes());
                n[e + 8..e + 12].copy_from_slice(&phys.to_le_bytes());
            } else {
                n[e + 4..e + 8].copy_from_slice(&phys.to_le_bytes());
            }
        }
        n
    }

    fn runs(fs: &Fs, disk: Vec<u8>, node: &[u8], upto: u64) -> (Vec<(u64, u64, u64, bool)>, bool) {
        let mut cur = Cursor::new(disk);
        let len = cur.get_ref().len() as u64;
        let mut v = Vol {
            disk: &mut cur,
            len,
            max: 1 << 20,
        };
        let mut m = Map {
            fs,
            upto,
            runs: Vec::new(),
            next: 0,
            nodes: 0,
        };
        let flow = m.extents(&mut v, node, None);
        let runs = m
            .runs
            .iter()
            .map(|r| (r.logical, r.phys, r.len, r.zero))
            .collect();
        (runs, !matches!(flow, Flow::Bad))
    }

    #[test]
    fn the_extents_of_a_leaf_are_its_runs_and_a_preallocated_one_reads_as_zeros() {
        let f = fs(1024);
        let leaf = node(0, &[(0, 4, 100), (10, 32768 + 5, 200), (20, 0, 300)]);
        let (r, ok) = runs(&f, vec![], &leaf, 100);
        assert!(ok);
        // A length of 0 is no extent.
        assert_eq!(r, [(0, 100, 4, false), (10, 200, 5, true)]);
    }

    #[test]
    fn extents_are_followed_through_an_index_to_the_blocks_it_wants() {
        let f = fs(1024);
        let mut disk = vec![0u8; 8192];
        let a = node(0, &[(0, 2, 50), (2, 2, 60)]);
        let b = node(0, &[(100, 3, 70)]);
        disk[2048..2048 + a.len()].copy_from_slice(&a);
        disk[3072..3072 + b.len()].copy_from_slice(&b);
        let root = node(1, &[(0, 0, 2), (100, 0, 3)]);
        let (r, ok) = runs(&f, disk.clone(), &root, 1000);
        assert!(ok);
        assert_eq!(r.len(), 3);
        assert_eq!(r[2], (100, 70, 3, false));
        // Only the first node is read when nothing past block 50 is wanted.
        let (r, ok) = runs(&f, disk, &root, 50);
        assert!(ok);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn extents_out_of_order_or_overlapping_are_not_a_map() {
        let f = fs(1024);
        let (_, ok) = runs(&f, vec![], &node(0, &[(10, 2, 1), (5, 2, 9)]), 100);
        assert!(!ok, "out of order");
        let (r, ok) = runs(&f, vec![], &node(0, &[(0, 10, 1), (5, 2, 9)]), 100);
        assert!(!ok && r.len() == 1, "overlapping");
    }

    #[test]
    fn a_node_that_is_not_one_is_not_followed() {
        let f = fs(1024);
        let mut bad = node(0, &[(0, 1, 1)]);
        bad[0] = 0;
        assert!(!runs(&f, vec![], &bad, 10).1, "magic");
        let mut more = node(0, &[(0, 1, 1)]);
        more[2..4].copy_from_slice(&5u16.to_le_bytes());
        assert!(!runs(&f, vec![], &more, 10).1, "more entries than room");
        assert!(!runs(&f, vec![], &node(6, &[(0, 0, 1)]), 10).1, "too tall");
        // An index that points at a node of the wrong height.
        let mut disk = vec![0u8; 4096];
        let leaf = node(1, &[(0, 0, 1)]);
        disk[2048..2048 + leaf.len()].copy_from_slice(&leaf);
        assert!(!runs(&f, disk, &node(1, &[(0, 0, 2)]), 10).1, "height");
        // An index that points past the volume.
        assert!(!runs(&f, vec![0; 1024], &node(1, &[(0, 0, 9)]), 10).1);
    }

    #[test]
    fn a_block_map_is_followed_through_its_three_levels() {
        let f = fs(1024);
        // 256 pointers to a block: direct blocks 0 to 11, then 12 to 267 by
        // the first level, then 268 to 65803 by the second, then the third.
        let mut disk = vec![0u8; 16 * 1024];
        let put = |disk: &mut Vec<u8>, block: usize, slot: usize, ptr: u32| {
            disk[block * 1024 + slot * 4..][..4].copy_from_slice(&ptr.to_le_bytes());
        };
        put(&mut disk, 3, 0, 500); // indirect block 3: block 12 is at 500
        put(&mut disk, 3, 1, 501);
        put(&mut disk, 5, 0, 4); // double indirect 5 -> indirect 4
        put(&mut disk, 4, 2, 900); // block 268 + 2 is at 900
        put(&mut disk, 8, 0, 7); // triple indirect 8 -> double 7 -> indirect 6
        put(&mut disk, 7, 0, 6);
        put(&mut disk, 6, 0, 1200); // block 268 + 65536 is at 1200
        let mut i_block = [0u8; 60];
        for (slot, ptr) in [(0, 40), (1, 41), (3, 43), (12, 3), (13, 5), (14, 8)] {
            i_block[slot * 4..][..4].copy_from_slice(&u32::to_le_bytes(ptr));
        }
        let mut cur = Cursor::new(disk);
        let mut v = Vol {
            disk: &mut cur,
            len: 16 * 1024,
            max: 1 << 20,
        };
        let mut m = Map {
            fs: &f,
            upto: 1 << 20,
            runs: Vec::new(),
            next: 0,
            nodes: 0,
        };
        assert!(!matches!(m.blocks(&mut v, &i_block), Flow::Bad));
        let got: Vec<_> = m.runs.iter().map(|r| (r.logical, r.phys, r.len)).collect();
        assert_eq!(
            got,
            [
                (0, 40, 2),
                (3, 43, 1),
                (12, 500, 2),
                (270, 900, 1),
                (65804, 1200, 1)
            ]
        );
    }

    #[test]
    fn a_block_map_stops_at_the_blocks_wanted() {
        let f = fs(1024);
        let mut i_block = [0u8; 60];
        for slot in 0..12usize {
            i_block[slot * 4..][..4].copy_from_slice(&(100 + slot as u32).to_le_bytes());
        }
        let mut cur = Cursor::new(vec![0u8; 1024]);
        let mut v = Vol {
            disk: &mut cur,
            len: 1024,
            max: 1 << 20,
        };
        let mut m = Map {
            fs: &f,
            upto: 5,
            runs: Vec::new(),
            next: 0,
            nodes: 0,
        };
        m.blocks(&mut v, &i_block);
        assert_eq!(m.runs.len(), 1);
        assert_eq!(m.runs[0].len, 5);
    }

    fn entry(ino: u32, rec: u16, name: &str) -> Vec<u8> {
        let mut e = vec![0u8; usize::from(rec)];
        e[0..4].copy_from_slice(&ino.to_le_bytes());
        e[4..6].copy_from_slice(&rec.to_le_bytes());
        e[6] = name.len() as u8;
        e[8..8 + name.len()].copy_from_slice(name.as_bytes());
        e
    }

    #[test]
    fn the_entries_of_a_block_are_its_live_names() {
        let block = [
            entry(2, 12, "."),
            entry(2, 12, ".."),
            entry(5, 12, "a"),
            // Deleted: no inode.
            entry(0, 16, "gone"),
            entry(7, 1024 - 52, "b.txt"),
        ]
        .concat();
        let mut out = Vec::new();
        assert!(dirents(&block, 1024, &mut out, 100));
        assert_eq!(out, [("a".to_string(), 5), ("b.txt".to_string(), 7)]);
        // As many as are wanted.
        let mut out = Vec::new();
        assert!(dirents(&block, 1024, &mut out, 1));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn a_block_whose_entries_do_not_add_up_is_damaged() {
        // An entry's header, and `total` bytes in all.
        let raw = |rec: u16, name_len: u8, total: usize| {
            let mut e = vec![0u8; total];
            e[0] = 5;
            e[4..6].copy_from_slice(&rec.to_le_bytes());
            e[6] = name_len;
            e
        };
        for (what, bad) in [
            ("a length of 0 never moves on", raw(0, 1, 16)),
            ("a length that is not a multiple of 4", raw(10, 1, 16)),
            ("a length under the header", raw(4, 0, 16)),
            ("a name longer than its entry", raw(12, 9, 12)),
            ("an entry that runs past the block", raw(24, 1, 16)),
            ("less than a header left", vec![0; 4]),
        ] {
            let mut out = Vec::new();
            assert!(!dirents(&bad, 1024, &mut out, 100), "{what}");
        }
    }

    #[test]
    fn the_length_of_an_entry_is_stored_as_the_block_size_says() {
        assert_eq!(rec_len(12, 4096), 12);
        assert_eq!(rec_len(0, 65536), 65536);
        assert_eq!(rec_len(u16::MAX, 65536), 65536);
        assert_eq!(rec_len(0x0104, 65536), 0x0104);
        // The two low bits stand for bits 16 and 17.
        assert_eq!(rec_len(0x0105, 65536), 0x1_0104);
    }

    #[test]
    fn the_superblock_copies_are_in_the_groups_that_have_them() {
        let mut f = fs(4096);
        let have = |f: &Fs| (0..60).filter(|&g| f.has_super(g)).collect::<Vec<_>>();
        assert_eq!(have(&f), [0, 1, 3, 5, 7, 9, 25, 27, 49]);
        f.sparse = false;
        assert_eq!(have(&f).len(), 60);
        f.sparse = true;
        f.sparse2 = true;
        f.backup = [1, 40];
        assert_eq!(have(&f), [0, 1, 40]);
    }

    #[test]
    fn the_data_kept_in_the_inode_is_found_by_its_name() {
        let mut raw = vec![0u8; 256];
        raw[128..130].copy_from_slice(&32u16.to_le_bytes());
        let at = 128 + 32;
        raw[at..at + 4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
        // An entry of another name first, then "data" in index 7 (system).
        let mut e = vec![0u8; 16 + 4];
        e[0] = 4;
        e[1] = 7;
        e[16..20].copy_from_slice(b"junk");
        e.extend_from_slice(&[0; 16]);
        let d = e.len() - 16;
        e[d] = 4;
        e[d + 1] = 7;
        e[d + 2..d + 4].copy_from_slice(&80u16.to_le_bytes());
        e[d + 8..d + 12].copy_from_slice(&5u32.to_le_bytes());
        e.extend_from_slice(b"data");
        raw[at + 4..at + 4 + e.len()].copy_from_slice(&e);
        raw[at + 4 + 80..at + 4 + 85].copy_from_slice(b"hello");
        assert_eq!(system_data(&raw), Some(&b"hello"[..]));
        // A value that runs past the inode is no value.
        raw[at + 4 + d + 8..at + 4 + d + 12].copy_from_slice(&500u32.to_le_bytes());
        assert_eq!(system_data(&raw), None);
        raw[at] = 0;
        assert_eq!(system_data(&raw), None);
    }
}
