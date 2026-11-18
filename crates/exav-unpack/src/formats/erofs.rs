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
//! (with holes) is read, and so is a file stored compressed (see below). A file
//! in chunks on another device is reported, not read. A symbolic link or a
//! device node holds no file's bytes and is not emitted. The checksum is not
//! checked.
//!
//! A compressed file is a list of extents, each the bytes of one physical
//! cluster (a run of blocks) decoded alone, with LZ4, LZMA, DEFLATE or Zstandard.
//! An index of logical clusters, one per block of the file, says where each
//! extent begins and how long it is, as a head and the non-heads after it; the
//! index is the full one (8 bytes a cluster) or the compact one (a block address
//! and cluster types packed, 2 or 16 clusters at a time). A cluster that is not
//! compressed is stored plain, or rotated (interlaced). The last extent can be
//! kept after the index (tail packing). The file is read one extent at a time:
//! what is held is the index in a window, the coded bytes of one physical
//! cluster and its decoder, whose output is read 64 KiB at a time. A file that
//! keeps its tail in the packed inode (fragments), or has the extent records
//! of the newer format, is reported, not read.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashSet;
use std::io::{Cursor, Read};

use super::vol::{
    Attrs, Emit, Fill, Got, List, Next, Piece, Pieces, Plan, Step, UNREADABLE, Vol, give, le16,
    le32, le64, read_file,
};
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, LimitHit, Mtime};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// The most a directory is, bytes.
const MAX_DIR: u64 = 64 << 20;

/// How the data of an inode is laid out.
const FLAT_PLAIN: u16 = 0;
const COMPRESSED_FULL: u16 = 1;
const FLAT_INLINE: u16 = 2;
const COMPRESSED_COMPACT: u16 = 3;
const CHUNK_BASED: u16 = 4;

/// The superblock's incompatible features that matter to compressed files. The
/// first is also the flag of the configurations of the algorithms.
const BIG_PCLUSTER: u32 = 0x2;
const COMPR_CFGS: u32 = 0x2;

/// The header's flags (`h_advise`) of a compressed file. The first is, in the
/// full layout, the flag of the newer format with extent records.
const COMPACTED_2B: u16 = 0x1;
const EXTENTS: u16 = 0x1;
const BIG_PCLUSTER_1: u16 = 0x2;
const BIG_PCLUSTER_2: u16 = 0x4;
const INLINE_PCLUSTER: u16 = 0x8;
const INTERLACED_PCLUSTER: u16 = 0x10;
const FRAGMENT_PCLUSTER: u16 = 0x20;
/// The top bit of the header's last byte: the whole file is in the packed
/// inode.
const FRAGMENT_INODE: u8 = 0x80;

/// The compression algorithms, as the header numbers them.
const LZ4: u8 = 0;
const LZMA: u8 = 1;
const DEFLATE: u8 = 2;
const ZSTD: u8 = 3;

/// The types of a logical cluster.
const PLAIN: u8 = 0;
const HEAD1: u8 = 1;
const NONHEAD: u8 = 2;
const HEAD2: u8 = 3;
/// In a non-head, the flag that makes its distance the number of blocks of
/// the physical cluster.
const D0_CBLKCNT: u32 = 1 << 11;

/// How much of a file's index is read at a time.
const INDEX_WINDOW: usize = 4096;

/// How much of a compressed file one step gives.
const CHUNK: usize = 1 << 16;

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
    /// Whether physical clusters may be longer than a block, and how large a
    /// dictionary the LZMA streams were made with (0: not said).
    big: bool,
    lzma_dict: u32,
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
                        return Got::Partial(Vec::new(), UNREADABLE);
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
                None => Got::Partial(Vec::new(), NO_CHUNKS),
            },
            COMPRESSED_FULL | COMPRESSED_COMPACT => match Zfile::open(self, v, ino) {
                Ok(z) => read_file(v, z, size, cap),
                Err(why) => Got::Why(why),
            },
            _ => Got::Why("EROFS file in a data layout exav does not read"),
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
    let incompat = le32(&b, 80);
    let lzma_dict = match incompat & COMPR_CFGS != 0 {
        // The configurations follow the superblock, which is 128 bytes and
        // the extension slots of 16.
        true => {
            let slots = 16u64.saturating_mul(u64::from(b[13]));
            let after = 1024u64.saturating_add(128).saturating_add(slots);
            lzma_dict(v, after, le16(&b, 84))?
        }
        false => 0,
    };
    let fs = Erofs {
        bs,
        meta,
        root: u64::from(le16(&b, 14)),
        big: incompat & BIG_PCLUSTER != 0,
        lzma_dict,
    };
    // The root is a directory.
    let root = fs.inode(v, fs.root)?;
    (root.mode & S_IFMT == S_IFDIR).then_some(fs)
}

/// The dictionary size the LZMA streams were made with, from the
/// configurations that follow the superblock: for each algorithm of the bitmap
/// `algs`, in the order of their numbers, a length and that many bytes. 0 where
/// the LZMA stream has none.
fn lzma_dict(v: &mut Vol, mut at: u64, algs: u16) -> Option<u32> {
    let mut dict = 0;
    for alg in 0..16u16 {
        if algs & (1 << alg) == 0 {
            continue;
        }
        let len = u64::from(le16(&v.at(at, 2)?, 0));
        let start = at.checked_add(2)?;
        if alg == u16::from(LZMA) {
            dict = le32(&v.at(start, crate::bytes::to_usize(len.min(4)))?, 0);
        }
        at = start.checked_add(len)?;
    }
    Some(dict)
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

const PACKED: &str = "EROFS file whose data is in the packed inode (fragments) not read";
const EXTENT_FORMAT: &str = "EROFS compressed file in the format with extent records not read";
const DAMAGED: &str = "EROFS compressed file with a damaged header";
const NO_CHUNKS: &str = "EROFS file with a chunk format exav does not read";
const NO_EXTENT: &str = "EROFS compressed file whose map of extents is unreadable or damaged";
const NO_PLAIN: &str = "EROFS compressed file with a stored extent longer than its blocks";
const OVER_LIMIT: &str =
    "EROFS compressed file with a physical cluster over the buffer limit (--max-object-bytes)";
const NO_CODED: &str = "EROFS compressed file with an extent whose coded bytes could not be opened";
const CUT_CODED: &str = "EROFS compressed file whose coded bytes did not decode to their extent";

/// A logical cluster of a compressed file, as its index says.
struct Lcl {
    kind: u8,
    /// Where in the cluster the extent that starts there starts (a head), or
    /// the cluster's size (a non-head).
    clusterofs: u64,
    /// In a non-head, how many clusters back its head is, and how many on the
    /// next one.
    delta0: u64,
    delta1: u64,
    /// In a head, the block of its physical cluster, and in a non-head that
    /// says it, how many blocks the physical cluster has.
    pblk: u64,
    cblks: Option<u64>,
    /// Where the index goes on after this cluster's pack.
    next: u64,
}

/// An extent of a file: `llen` bytes from `la`, stored as `at` says.
struct Ext {
    la: u64,
    llen: u64,
    at: Where,
}

enum Where {
    Hole,
    /// Stored as it is, in a physical cluster of `plen` bytes at `pa`; the
    /// first block's share of it is at the end when it is interlaced.
    Plain {
        pa: u64,
        plen: u64,
        interlaced: bool,
    },
    /// Coded with `algo`, in `plen` bytes at `pa`.
    Coded {
        pa: u64,
        plen: u64,
        algo: u8,
    },
}

/// The last extent of a file, whose coded bytes are kept after its index.
struct Tail {
    /// The cluster of its head, and the place and length of its bytes.
    lcn: u64,
    at: u64,
    len: u64,
}

/// The bytes of an extent that are being given.
enum Src {
    Zeros,
    /// Stretches of the volume (offset, length), in order, and which is next.
    Disk([(u64, u64); 2], usize),
    Coded(Box<dyn Read>),
}

struct Run {
    left: u64,
    src: Src,
}

/// A compressed file, produced an extent at a time, each decoded as it is read.
struct Zfile {
    bs: u64,
    size: u64,
    compact: bool,
    advise: u16,
    /// A logical cluster is `1 << lb` bytes.
    lb: u32,
    /// The algorithms of the two kinds of head.
    algo: [u8; 2],
    /// Where the index begins, and how many clusters it has.
    ebase: u64,
    total: u64,
    lzma_dict: u32,
    tail: Option<Tail>,
    /// A window of the index, and where it starts.
    index: Vec<u8>,
    index_at: u64,
    /// The next byte of the file, the extent being given, and the bytes of
    /// holes given.
    la: u64,
    run: Option<Run>,
    holes: u64,
}

impl Zfile {
    /// The compressed file `ino`, or why it is not read.
    fn open(fs: &Erofs, v: &mut Vol, ino: &Inode) -> Result<Zfile, &'static str> {
        let compact = ino.layout == COMPRESSED_COMPACT;
        let pos = ino.after.checked_next_multiple_of(8).ok_or(DAMAGED)?;
        let h = v.at(pos, 8).ok_or(DAMAGED)?;
        if h[7] & FRAGMENT_INODE != 0 {
            return Err(PACKED);
        }
        let advise = le16(&h, 4);
        let bits = fs.bs.trailing_zeros().saturating_add(u32::from(h[7] & 15));
        let algo = [h[6] & 15, h[6] >> 4];
        if algo.iter().any(|&a| a > ZSTD) {
            return Err(DAMAGED);
        }
        if !compact && advise & EXTENTS != 0 {
            return Err(EXTENT_FORMAT);
        }
        let big = advise & (BIG_PCLUSTER_1 | BIG_PCLUSTER_2);
        // Both or neither of the two, in the compact layout.
        let mixed = compact && (big & BIG_PCLUSTER_1 != 0) != (big & BIG_PCLUSTER_2 != 0);
        if (big != 0 && !fs.big) || mixed || bits > 31 {
            return Err(DAMAGED);
        }
        if advise & FRAGMENT_PCLUSTER != 0 {
            return Err(PACKED);
        }
        // The index follows the header, and in the full layout 8 bytes more.
        let skip = if compact { 8 } else { 16 };
        let mut z = Zfile {
            bs: fs.bs,
            size: ino.size,
            compact,
            advise,
            lb: bits,
            algo,
            ebase: pos.checked_add(skip).ok_or(DAMAGED)?,
            total: ino.size.div_ceil(fs.bs),
            lzma_dict: fs.lzma_dict,
            tail: None,
            index: Vec::new(),
            index_at: 0,
            la: 0,
            run: None,
            holes: 0,
        };
        let idata = u64::from(le16(&h, 2));
        if advise & INLINE_PCLUSTER != 0 && idata != 0 {
            z.tail = Some(z.find_tail(v, idata).ok_or(DAMAGED)?);
        }
        Ok(z)
    }

    /// `n` bytes of the index at `off`, through a window.
    fn index(&mut self, v: &mut Vol, off: u64, n: usize) -> Option<&[u8]> {
        let end = off.checked_add(n as u64)?;
        let held = self.index_at.checked_add(self.index.len() as u64)?;
        if off < self.index_at || end > held {
            self.index.clear();
            let room = v.len.checked_sub(off)?;
            let want = crate::bytes::to_usize(room.min(INDEX_WINDOW as u64));
            if want < n || !v.append(off, want, &mut self.index) {
                self.index.clear();
                return None;
            }
            self.index_at = off;
        }
        let from = crate::bytes::to_usize(off.saturating_sub(self.index_at));
        self.index.get(from..from.checked_add(n)?)
    }

    fn load(&mut self, v: &mut Vol, lcn: u64, ahead: bool) -> Option<Lcl> {
        match self.compact {
            true => self.load_compact(v, lcn, ahead),
            false => self.load_full(v, lcn),
        }
    }

    /// Cluster `lcn` of the full index: 8 bytes each.
    fn load_full(&mut self, v: &mut Vol, lcn: u64) -> Option<Lcl> {
        let pos = self.ebase.checked_add(lcn.checked_mul(8)?)?;
        let e: [u8; 8] = self.index(v, pos, 8)?.try_into().ok()?;
        let advise = le16(&e, 0);
        let kind = (advise & 3) as u8;
        let next = pos.checked_add(8)?;
        let lsz = 1u64 << self.lb;
        if kind == NONHEAD {
            let mut d0 = u32::from(le16(&e, 4));
            let mut cblks = None;
            if d0 & D0_CBLKCNT != 0 {
                if self.advise & (BIG_PCLUSTER_1 | BIG_PCLUSTER_2) == 0 {
                    return None;
                }
                cblks = Some(u64::from(d0 & !D0_CBLKCNT));
                d0 = 1;
            }
            return Some(Lcl {
                kind,
                clusterofs: lsz,
                delta0: u64::from(d0),
                delta1: u64::from(le16(&e, 6)),
                pblk: 0,
                cblks,
                next,
            });
        }
        let clusterofs = u64::from(le16(&e, 2));
        (clusterofs < lsz).then(|| Lcl {
            kind,
            clusterofs,
            delta0: 0,
            delta1: 0,
            pblk: u64::from(le32(&e, 4)),
            cblks: None,
            next,
        })
    }

    /// Cluster `lcn` of the compact index: packs of 2 clusters in 8 bytes or
    /// of 16 in 32, each ending in a 4-byte block address, the packs starting
    /// at a multiple of their size. `ahead` also finds how far the next head is.
    fn load_compact(&mut self, v: &mut Vol, lcn: u64, ahead: bool) -> Option<Lcl> {
        let lb = self.lb;
        if lcn >= self.total || lb > 14 {
            return None;
        }
        // A few clusters of 4 bytes bring the index to a multiple of 32, then
        // packs of 16 clusters of 2 bytes as long as they fit, then 4 bytes.
        let a4 = (32u64.saturating_sub(self.ebase % 32) / 4) & 7;
        let a2 = if self.advise & COMPACTED_2B != 0 && a4 < self.total {
            (self.total.saturating_sub(a4) / 16).saturating_mul(16)
        } else {
            0
        };
        let (mut pos, mut shift, mut l) = (self.ebase, 2u32, lcn);
        if l >= a4 {
            pos = pos.checked_add(a4.checked_mul(4)?)?;
            l = l.saturating_sub(a4);
            if l < a2 {
                shift = 1;
            } else {
                pos = pos.checked_add(a2.checked_mul(2)?)?;
                l = l.saturating_sub(a2);
            }
        }
        pos = pos.checked_add(l.checked_shl(shift)?)?;
        let (vcnt, pack) = match shift {
            2 => (2usize, 8usize),
            _ if lb <= 12 => (16, 32),
            _ => return None,
        };
        let start = pos & !(pack as u64).saturating_sub(1);
        let i = crate::bytes::to_usize(pos.saturating_sub(start) >> shift);
        let mut b = [0u8; 32];
        b[..pack].copy_from_slice(self.index(v, start, pack)?);
        let next = start.checked_add(pack as u64)?;
        // The entries are `encode` bits, a `lobits` number and 2 of type.
        let encode = pack
            .saturating_sub(4)
            .saturating_mul(8)
            .checked_div(vcnt)
            .unwrap_or(0);
        let lobits = lb.max(12);
        let low = 1u32
            .checked_shl(lobits)
            .map_or(u32::MAX, |m| m.saturating_sub(1));
        let entry = |k: usize| -> (u32, u8) {
            let bit = encode.saturating_mul(k);
            let w = le32(&b, bit / 8) >> (bit % 8);
            (w & low, ((w >> lobits) & 3) as u8)
        };
        let big = self.advise & BIG_PCLUSTER_1 != 0;
        let (lo, kind) = entry(i);
        if kind == NONHEAD {
            // How far the next head is: this entry and those after it that are
            // not heads, and where they run to the end of the pack, how many
            // more the last of them says.
            let mut delta1 = 0u64;
            if ahead {
                for j in i..vcnt {
                    let (l, t) = entry(j);
                    if t != NONHEAD {
                        break;
                    }
                    delta1 = delta1.saturating_add(1);
                    if j.saturating_add(1) == vcnt && l & D0_CBLKCNT == 0 {
                        delta1 = delta1.saturating_add(u64::from(l.saturating_sub(1)));
                    }
                }
            }
            let mut lcl = Lcl {
                kind,
                clusterofs: 1u64 << lb,
                delta0: u64::from(lo),
                delta1,
                pblk: 0,
                cblks: None,
                next,
            };
            if lo & D0_CBLKCNT != 0 {
                if self.advise & (BIG_PCLUSTER_1 | BIG_PCLUSTER_2) == 0 {
                    return None;
                }
                lcl.cblks = Some(u64::from(lo & !D0_CBLKCNT));
                lcl.delta0 = 1;
            } else if i.saturating_add(1) == vcnt {
                // The last entry holds the distance to the next head, and its
                // distance back is that of the entry before it, plus one.
                let (plo, pkind) = entry(i.saturating_sub(1));
                let back = match pkind {
                    NONHEAD if plo & D0_CBLKCNT != 0 => 1,
                    NONHEAD => plo,
                    _ => 0,
                };
                lcl.delta0 = u64::from(back).saturating_add(1);
            }
            return Some(lcl);
        }
        if u64::from(lo) >= 1u64 << lb {
            return None;
        }
        // The block of the head: the pack's base address and the blocks of the
        // physical clusters of the heads before it in the pack.
        let mut blocks = if big { 0u64 } else { 1 };
        let mut j = i as i64;
        while j > 0 {
            j = j.saturating_sub(1);
            let (l, t) = entry(j as usize);
            if big {
                if t == NONHEAD {
                    if l & D0_CBLKCNT != 0 {
                        j = j.saturating_sub(1);
                        blocks = blocks.saturating_add(u64::from(l & !D0_CBLKCNT));
                    } else if l <= 1 {
                        return None;
                    } else {
                        j = j.saturating_sub(i64::from(l).saturating_sub(2));
                    }
                } else {
                    blocks = blocks.saturating_add(1);
                }
            } else {
                if t == NONHEAD {
                    j = j.saturating_sub(i64::from(l));
                }
                if j >= 0 {
                    blocks = blocks.saturating_add(1);
                }
            }
        }
        let base = u64::from(le32(&b, pack.saturating_sub(4)));
        Some(Lcl {
            kind,
            clusterofs: u64::from(lo),
            delta0: 0,
            delta1: 0,
            pblk: base.checked_add(blocks)?,
            cblks: None,
            next,
        })
    }

    /// The head that cluster `lcn`, `dist` clusters ahead of its head or of a
    /// non-head that leads to it, belongs to: its place and its entry. The
    /// blocks of its physical cluster are in `known` if a non-head said.
    fn lookback(
        &mut self,
        v: &mut Vol,
        mut lcn: u64,
        mut dist: u64,
        known: &mut Option<u64>,
    ) -> Option<(u64, Lcl)> {
        while dist > 0 && lcn >= dist {
            lcn = lcn.saturating_sub(dist);
            let l = self.load(v, lcn, false)?;
            if l.kind == NONHEAD {
                *known = l.cblks.or(*known);
                dist = l.delta0;
                continue;
            }
            return Some((lcn, l));
        }
        None
    }

    /// The head of the extent that has the byte `la`, and where that extent
    /// starts.
    fn head(
        &mut self,
        v: &mut Vol,
        la: u64,
        known: &mut Option<u64>,
    ) -> Option<(u64, Lcl, u64, u64)> {
        let lsz = 1u64 << self.lb;
        let lcn = la >> self.lb;
        let endoff = la & lsz.saturating_sub(1);
        let m = self.load(v, lcn, false)?;
        *known = m.cblks;
        let next = m.next;
        let (hlcn, head) = if m.kind != NONHEAD && endoff >= m.clusterofs {
            (lcn, m)
        } else {
            // Before the head of its own cluster, the byte is the end of the
            // extent before.
            let back = if m.kind != NONHEAD { 1 } else { m.delta0 };
            self.lookback(v, lcn, back, known)?
        };
        let start = hlcn.checked_mul(lsz)?.checked_add(head.clusterofs)?;
        Some((hlcn, head, start, next))
    }

    /// Where the last extent's coded bytes are, kept after the index: right
    /// after the pack of the last cluster, `idata` bytes.
    fn find_tail(&mut self, v: &mut Vol, idata: u64) -> Option<Tail> {
        let last = self.size.checked_sub(1)?;
        let mut known = None;
        let (lcn, _, _, next) = self.head(v, last, &mut known)?;
        let within = next.checked_rem(self.bs)?;
        (within.checked_add(idata)? <= self.bs).then_some(Tail {
            lcn,
            at: next,
            len: idata,
        })
    }

    /// How many blocks the physical cluster of the head at `hlcn` has.
    fn blocks(&mut self, v: &mut Vol, hlcn: u64, head: &Lcl, known: Option<u64>) -> Option<u64> {
        let after = hlcn.checked_add(1)?;
        let big = match head.kind {
            HEAD1 => self.advise & BIG_PCLUSTER_1 != 0,
            _ => self.advise & BIG_PCLUSTER_2 != 0,
        };
        // Without the flag, or at the end of the file, it is one block.
        if !big || after.checked_mul(1u64 << self.lb)? >= self.size {
            return Some(known.unwrap_or(1));
        }
        if let Some(k) = known {
            return Some(k);
        }
        let n = self.load(v, after, false)?;
        match n.kind {
            NONHEAD if n.delta0 != 1 => None,
            NONHEAD => n.cblks,
            _ => Some(1),
        }
    }

    /// How many bytes the extent that starts at `start`, whose head is
    /// cluster `hlcn`, has: to the next head, or to the end of the file.
    fn length(&mut self, v: &mut Vol, hlcn: u64, start: u64) -> Option<u64> {
        let mut lcn = hlcn;
        loop {
            if lcn.checked_mul(1u64 << self.lb)? >= self.size {
                return self.size.checked_sub(start);
            }
            let l = self.load(v, lcn, true)?;
            let mut step = l.delta1;
            if l.kind == NONHEAD {
                if step == 0 {
                    step = 1;
                }
            } else if lcn != hlcn {
                // The next head ends it.
                return lcn
                    .checked_mul(1u64 << self.lb)?
                    .checked_add(l.clusterofs)?
                    .checked_sub(start);
            } else {
                step = 1;
            }
            lcn = lcn.checked_add(step)?;
        }
    }

    /// The extent that starts at byte `la`.
    fn extent(&mut self, v: &mut Vol, la: u64) -> Option<Ext> {
        let mut known = None;
        let (hlcn, head, start, _) = self.head(v, la, &mut known)?;
        if start != la {
            return None;
        }
        let llen = self.length(v, hlcn, start)?;
        if llen == 0 {
            return None;
        }
        let tail = self
            .tail
            .as_ref()
            .filter(|t| t.lcn == hlcn)
            .map(|t| (t.at, t.len));
        let (pa, plen) = match tail {
            Some(t) => t,
            None => {
                let blocks = self.blocks(v, hlcn, &head, known)?;
                if blocks == 0 || head.pblk == u64::from(u32::MAX) {
                    return Some(Ext {
                        la,
                        llen,
                        at: Where::Hole,
                    });
                }
                (
                    head.pblk.checked_mul(self.bs)?,
                    blocks.checked_mul(self.bs)?,
                )
            }
        };
        let at = match head.kind {
            PLAIN => Where::Plain {
                pa,
                plen,
                interlaced: self.advise & INTERLACED_PCLUSTER != 0 && tail.is_none(),
            },
            kind => Where::Coded {
                pa,
                plen,
                algo: self.algo[usize::from(kind == HEAD2)],
            },
        };
        Some(Ext { la, llen, at })
    }

    /// The bytes of `e` as they are read.
    fn start(&mut self, v: &mut Vol, e: Ext) -> Option<Run> {
        let src = match e.at {
            Where::Hole => Src::Zeros,
            Where::Plain {
                pa,
                plen,
                interlaced,
            } => {
                if e.llen > plen {
                    return None;
                }
                // The share of the first block is kept at the end, so that a
                // block can be read in place.
                let first = match interlaced {
                    true => self
                        .bs
                        .saturating_sub(e.la.checked_rem(self.bs)?)
                        .min(e.llen),
                    false => 0,
                };
                let at = pa.checked_add(plen.checked_sub(first)?)?;
                Src::Disk([(at, first), (pa, e.llen.checked_sub(first)?)], 0)
            }
            Where::Coded { pa, plen, algo } => {
                if plen > v.max as u64 {
                    return None;
                }
                let mut packed = v.at(pa, crate::bytes::to_usize(plen))?;
                // The coded bytes end the physical cluster, with zeros before.
                let lead = packed.iter().position(|&b| b != 0)?;
                packed.drain(..lead);
                Src::Coded(self.decoder(algo, packed, e.llen, v.max as u64)?)
            }
        };
        Some(Run { left: e.llen, src })
    }

    /// A reader of the first `llen` bytes the coded bytes `packed` decode to.
    fn decoder(&self, algo: u8, packed: Vec<u8>, llen: u64, max: u64) -> Option<Box<dyn Read>> {
        let input = Cursor::new(packed);
        Some(match algo {
            LZ4 => Box::new(super::lz4::BlockReader::new(input.into_inner(), llen)),
            LZMA => {
                // The first byte is the properties, inverted, and the range
                // coder's first byte, always 0, is not there.
                let mut packed = input.into_inner();
                let props = !*packed.first()?;
                *packed.first_mut()? = 0;
                // What the output can reach back to is no more than it is.
                let dict = match self.lzma_dict {
                    0 => u64::MAX,
                    d => u64::from(d),
                };
                let dict = u32::try_from(dict.min(llen.max(4096)).min(max.max(4096))).ok()?;
                let stream =
                    lzma_rust2::LzmaStream::new_with_props(llen, props, dict, None).ok()?;
                Box::new(super::lzma::SansIo::new(Cursor::new(packed), stream))
            }
            DEFLATE => Box::new(crate::inflate::Inflate::new(input).take(llen)),
            _ => Box::new(super::zstd::ZstdReader::new(input).take(llen)),
        })
    }
}

impl Fill for Zfile {
    fn holes(&self) -> u64 {
        self.holes
    }

    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        let mut run = match self.run.take() {
            Some(run) => run,
            None => {
                if self.la >= self.size {
                    return Step::End;
                }
                let Some(e) = self.extent(v, self.la) else {
                    return Step::Broken(NO_EXTENT);
                };
                // The last extent is as long as the file is.
                let e = Ext {
                    llen: e.llen.min(self.size.saturating_sub(self.la)),
                    ..e
                };
                let why = match e.at {
                    Where::Coded { plen, .. } if plen > v.max as u64 => OVER_LIMIT,
                    Where::Coded { .. } => NO_CODED,
                    _ => NO_PLAIN,
                };
                match self.start(v, e) {
                    Some(run) => run,
                    None => return Step::Broken(why),
                }
            }
        };
        let want = run.left.min(CHUNK as u64);
        let n = crate::bytes::to_usize(want);
        let base = out.len();
        let (got, cut) = match &mut run.src {
            Src::Zeros => {
                out.resize(base.saturating_add(n), 0);
                self.holes = self.holes.saturating_add(want);
                (want, "")
            }
            Src::Disk(pieces, at) => {
                let got = loop {
                    let Some(&(off, len)) = pieces.get(*at) else {
                        break 0;
                    };
                    if len == 0 {
                        *at = at.saturating_add(1);
                        continue;
                    }
                    let take = len.min(want);
                    if !v.append(off, crate::bytes::to_usize(take), out) {
                        break 0;
                    }
                    pieces[*at] = (off.saturating_add(take), len.saturating_sub(take));
                    break take;
                };
                (got, UNREADABLE)
            }
            Src::Coded(r) => {
                out.resize(base.saturating_add(n), 0);
                let k = r.read(&mut out[base..]).unwrap_or(0);
                out.truncate(base.saturating_add(k));
                (k as u64, CUT_CODED)
            }
        };
        if got == 0 {
            return Step::Broken(cut);
        }
        run.left = run.left.saturating_sub(got);
        self.la = self.la.saturating_add(got);
        if run.left > 0 {
            self.run = Some(run);
        }
        Step::More
    }
}

/// Walk an EROFS image given whole as a source.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    super::volumes::walk_source(src, budget, visit, walk_volume)
}

/// Walk the EROFS image `disk`, which is `len` bytes long, handing each file
/// to `visit`.
pub(crate) fn walk_volume(
    disk: &mut dyn super::vol::Disk,
    len: u64,
    budget: &mut Budget,
    visit: Emit,
) -> crate::Extracted {
    let max = crate::bytes::to_usize(budget.limits().max_buffer_bytes);
    let mut v = Vol { disk, len, max };
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
        let end = walk_volume(&mut Cursor::new(img), len, &mut budget, &mut |e, _| {
            let e = e.whole();
            out.push((e.name, e.data, e.unsupported));
            None
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
    fn a_file_in_chunks_of_a_size_no_chunk_has_is_reported_for_it() {
        let mut img = Img::new();
        // The chunk size is the block's, shifted by the low 5 bits.
        let f = img.inode(CHUNK_BASED, 0o100644, 100, 0x1F, b"");
        let root = img.dir(&[("f", f, 1)]);
        let (e, end) = walked(&img.finish(root), Limits::default());
        end.unwrap();
        assert_eq!(e[0].2, Some(NO_CHUNKS));
        assert!(e[0].1.is_empty());
    }

    #[test]
    fn a_compressed_file_with_no_index_and_a_chunk_on_another_device_are_reported() {
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
        // The index of "z" is not there: what it gives is not the file.
        assert!(by("z").2.is_some(), "{:?}", by("z").1.len());
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
        let (e, end) =
            collected(|emit| walk_volume(&mut Cursor::new(&img[..]), len, &mut budget, emit));
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
        let (e, end) =
            collected(|emit| walk_volume(&mut Cursor::new(&img[..]), len, &mut budget, emit));
        end.unwrap();
        assert_eq!(e.len(), 1);
        assert!(e[0].1, "read as it goes");
        let want: Vec<u8> = (0..n).flat_map(|_| pat(BS)).collect();
        assert_eq!(e[0].0.data, want);
    }
}
