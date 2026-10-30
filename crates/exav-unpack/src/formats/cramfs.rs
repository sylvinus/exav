//! cramfs: the files of an image, read where they lie.
//!
//! The small read-only filesystem of embedded Linux boot images and initial
//! ramdisks. The image is a `Read + Seek`, read where the walk goes: the
//! superblock, each directory's entries and each file's blocks. Only a file is
//! ever held, bounded by the buffer limit.
//!
//! ```text
//! superblock (76 bytes)   magic and signature, the root inode
//!   inode (12 bytes)      mode, size, and an offset in words: a directory's
//!                         entries, or a file's table of block ends
//!   directory             inodes, each followed by its name, padded to words
//!   file                  a table of where each 4 KiB block ends, then the
//!                         blocks, each deflated (zlib); a block that is
//!                         empty is a hole
//! ```
//!
//! Both byte orders are read, and an image that begins 512 bytes in (room for
//! boot code). A block that is stored as it is, as the extended block
//! pointers allow, is read; one that lies elsewhere than after the one before
//! it is reported. A symbolic link or a device node holds no file's bytes and
//! is not emitted. The image's checksum is not checked.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashSet;
use std::io::{Read, Seek};

use super::vol::{Attrs, Emit, Fill, Got, Step, Vol, be32, give, le32, read_file};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, LimitHit};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// Bytes in a block of a file.
const BLOCK: usize = 4096;

/// Superblock flag: block pointers carry flags of their own.
const EXT_BLOCK_POINTERS: u32 = 0x0000_0800;
/// Flags of an extended block pointer.
const BLK_UNCOMPRESSED: u32 = 1 << 31;
const BLK_DIRECT: u32 = 1 << 30;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

/// Whether `data`, the start of an image, holds a cramfs superblock, at the
/// start or 512 bytes in: its magic in either byte order and its signature.
pub(crate) fn is_cramfs(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Cramfs)
}

/// An inode.
#[derive(Clone)]
struct Inode {
    mode: u32,
    size: u64,
    /// Where its directory entries or its table of block ends are, in bytes
    /// from the start of the image, and how long its name is, in bytes.
    offset: u64,
    name_len: usize,
}

/// What the superblock says of the image.
struct Cram {
    be: bool,
    flags: u32,
    root: Inode,
}

impl Cram {
    fn word(&self, d: &[u8], at: usize) -> u32 {
        if self.be { be32(d, at) } else { le32(d, at) }
    }

    /// The inode in the 12 bytes `d`. The fields are bits of words laid out as
    /// the machine that made the image lays them out: from the low bit on in
    /// the small-endian image, from the high bit on in the other.
    fn inode(&self, d: &[u8]) -> Inode {
        let (w0, w1, w2) = (self.word(d, 0), self.word(d, 4), self.word(d, 8));
        let (mode, size, name_len, offset) = if self.be {
            (w0 >> 16, w1 >> 8, w2 >> 26, w2 & 0x03FF_FFFF)
        } else {
            (w0 & 0xFFFF, w1 & 0x00FF_FFFF, w2 & 63, w2 >> 6)
        };
        Inode {
            mode,
            size: u64::from(size),
            offset: u64::from(offset).saturating_mul(4),
            name_len: crate::bytes::to_usize(u64::from(name_len).saturating_mul(4)),
        }
    }

    /// The entries of the directory `dir`: name and inode. The flag is false
    /// where the directory is damaged. `left` counts the bytes of directories
    /// the walk may still read.
    fn entries(
        &self,
        v: &mut Vol,
        dir: &Inode,
        left: &mut u64,
        limit: usize,
    ) -> (Vec<(String, Inode)>, bool) {
        let mut out = Vec::new();
        if dir.size > *left {
            return (out, false);
        }
        *left = left.saturating_sub(dir.size);
        let Some(list) = v.at(dir.offset, crate::bytes::to_usize(dir.size)) else {
            return (out, false);
        };
        let mut pos = 0usize;
        while pos < list.len() {
            let Some(head) = crate::bytes::at(&list, pos, 12) else {
                return (out, false);
            };
            let inode = self.inode(head);
            let start = pos.saturating_add(12);
            let Some(name) = crate::bytes::at(&list, start, inode.name_len) else {
                return (out, false);
            };
            // The name is null-padded to a whole number of words.
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            pos = start.saturating_add(inode.name_len);
            if out.len() >= limit {
                return (out, true);
            }
            out.push((String::from_utf8_lossy(&name[..end]).into_owned(), inode));
        }
        (out, true)
    }

    /// The bytes of a file: held when they are at most `cap`, else read as
    /// they go.
    fn file<'a>(&self, v: &'a mut Vol<'_>, f: &Inode, cap: u64) -> Got<'a> {
        if f.size == 0 {
            return Got::Whole(Vec::new());
        }
        let size = crate::bytes::to_usize(f.size);
        let blocks = size.div_ceil(BLOCK);
        let Some(ends) = v.at(f.offset, blocks.saturating_mul(4)) else {
            return Got::Why("cramfs file whose table of blocks is unreadable");
        };
        let fill = Blocks {
            ends,
            be: self.be,
            ext: self.flags & EXT_BLOCK_POINTERS != 0,
            // The first block follows the table, and each follows the one before.
            prev: f.offset.saturating_add((blocks as u64).saturating_mul(4)),
            i: 0,
            blocks,
            size,
        };
        read_file(v, fill, f.size, cap)
    }
}

/// The blocks of a file, read and inflated as they are wanted.
struct Blocks {
    /// Where each block ends.
    ends: Vec<u8>,
    be: bool,
    ext: bool,
    /// Where the next block starts.
    prev: u64,
    i: usize,
    blocks: usize,
    size: usize,
}

impl Fill for Blocks {
    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        if self.i >= self.blocks {
            return Step::End;
        }
        let at = self.i.saturating_mul(4);
        let raw = if self.be {
            be32(&self.ends, at)
        } else {
            le32(&self.ends, at)
        };
        let (stored, direct) = (
            self.ext && raw & BLK_UNCOMPRESSED != 0,
            self.ext && raw & BLK_DIRECT != 0,
        );
        let end = u64::from(if self.ext { raw & 0x3FFF_FFFF } else { raw });
        let want = BLOCK.min(self.size.saturating_sub(self.i.saturating_mul(BLOCK)));
        if direct || end < self.prev {
            return Step::Broken;
        }
        if end == self.prev {
            // A hole.
            out.resize(out.len().saturating_add(want), 0);
            self.i = self.i.saturating_add(1);
            return Step::More;
        }
        let len = crate::bytes::to_usize(end.saturating_sub(self.prev));
        // A block is a page, stored or deflated, and deflate adds a few bytes
        // to a page it cannot shrink.
        if len > BLOCK.saturating_mul(2) {
            return Step::Broken;
        }
        let Some(raw_block) = v.at(self.prev, len) else {
            return Step::Broken;
        };
        self.prev = end;
        let mut block = if stored {
            raw_block
        } else {
            match unzlib(&raw_block) {
                Some(b) => b,
                None => return Step::Broken,
            }
        };
        block.resize(want, 0);
        out.extend_from_slice(&block);
        self.i = self.i.saturating_add(1);
        Step::More
    }
}

/// A block inflated, to at most one block of bytes.
fn unzlib(src: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    crate::inflate::zlib_body(src)?
        .take((BLOCK as u64).saturating_add(1))
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= BLOCK).then_some(out)
}

/// The image's superblock, or `None` where it describes none that is read.
fn open(v: &mut Vol) -> Option<Cram> {
    for base in [0u64, 512] {
        let Some(b) = v.at(base, 76) else {
            continue;
        };
        if b.get(16..32) != Some(b"Compressed ROMFS".as_slice()) {
            continue;
        }
        let be = match b.get(0..4)? {
            [0x28, 0xCD, 0x3D, 0x45] => true,
            [0x45, 0x3D, 0xCD, 0x28] => false,
            _ => continue,
        };
        let mut cram = Cram {
            be,
            flags: 0,
            root: Inode {
                mode: 0,
                size: 0,
                offset: 0,
                name_len: 0,
            },
        };
        cram.flags = cram.word(&b, 8);
        cram.root = cram.inode(b.get(64..76)?);
        return (cram.root.mode & S_IFMT == S_IFDIR).then_some(cram);
    }
    None
}

/// Walk a cramfs image given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the cramfs image `disk`, which is `len` bytes long, handing each file
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
        .at(0, crate::bytes::to_usize(len.min(544)))
        .unwrap_or_default();
    if !is_cramfs(&head) {
        return Ok(None);
    }
    let Some(fs) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "cramfs open: the superblock or the root directory is unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    // The directories of an image are disjoint, so they are not more than it.
    let mut left = len;
    let mut damaged = false;
    let mut seen: HashSet<(u64, u64)> = HashSet::from([(fs.root.offset, fs.root.size)]);
    let mut stack = vec![(fs.root.clone(), String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        let (list, intact) = fs.entries(&mut v, &dir, &mut left, limit);
        damaged |= !intact;
        let mut below = Vec::new();
        for (name, inode) in list {
            budget.count_entry()?;
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match inode.mode & S_IFMT {
                S_IFDIR => {
                    if depth >= MAX_DEPTH {
                        damaged = true;
                    } else if seen.insert((inode.offset, inode.size)) {
                        below.push((inode, path, depth.saturating_add(1)));
                    }
                }
                S_IFREG => {
                    let attrs = Attrs {
                        mode: Some(inode.mode),
                        mtime: None,
                    };
                    if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                        fs.file(&mut v, &inode, cap)
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
            "cramfs walk: the image is damaged; the files before the damage were scanned".into(),
        ));
    }
    Ok(None)
}
