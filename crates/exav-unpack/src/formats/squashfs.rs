//! SquashFS 4: the files of an image, read where they lie.
//!
//! The filesystem of firmware, live images, AppImages and snaps: a read-only
//! tree in blocks that are each compressed on its own. The image is a
//! `Read + Seek`, read where the walk goes: the superblock, the blocks of the
//! tables the walk passes through, and each file's blocks. Only a file is ever
//! held, bounded by the buffer limit.
//!
//! ```text
//! superblock          block size, compression, where each table is, the root
//!   inode table       metadata blocks: one inode per file, with the sizes of
//!                     its data blocks, and the fragment its tail is in
//!   directory table   metadata blocks: runs of (name, inode) per directory
//!   fragment table    where each block that holds tails is
//!   data blocks       file contents, in blocks of the block size, each
//!                     compressed or not
//! ```
//!
//! A metadata block is at most 8 KiB once decompressed, behind a 2-byte header
//! that says whether it is compressed and how long it is. An inode or a
//! directory is addressed by the metadata block it starts in, and the offset
//! in it, and may go on into the next block. Both byte orders are read (an
//! image from a big-endian machine begins `sqsh`). The compressions are gzip,
//! LZMA, LZO, XZ, LZ4 and Zstandard. A sparse block reads as zeros. A symbolic
//! link or a device node holds no file's bytes and is not emitted. Versions
//! before 4 are reported, not read.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::rc::Rc;

use super::vol::{
    Attrs, Emit, Fill, Found, Got, Step, Vol, be16, be32, be64, give, le16, le32, le64, read_file,
};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, Entry, LimitHit, Mtime};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// What a metadata block holds once decompressed, at most.
const META: usize = 8192;

/// How many metadata blocks are kept.
const CACHED: usize = 64;

/// The most a directory's listing is, bytes.
const MAX_LISTING: u64 = 64 << 20;

/// The most data blocks of a file are read from a list.
const MAX_BLOCKS: u64 = 1 << 24;

/// The size of a fragment that is none.
const NO_FRAGMENT: u32 = 0xFFFF_FFFF;

/// `st_mode` file types.
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

/// Whether `data`, the start of an image, holds a SquashFS superblock's magic,
/// in either byte order.
pub(crate) fn is_squashfs(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Squashfs)
}

/// What the superblock says of the image.
struct Squash {
    be: bool,
    block_size: u64,
    compression: u16,
    fragments: u32,
    root: u64,
    inode_table: u64,
    dir_table: u64,
    frag_table: u64,
    /// The decompressed bytes of the metadata blocks read, by place, and the
    /// place of the block after.
    cache: HashMap<u64, (Rc<Vec<u8>>, u64)>,
    /// The last block of fragments read, and which.
    fragment: Option<(u32, Rc<Vec<u8>>)>,
}

/// What an inode is.
enum Kind {
    Dir {
        /// The directory table's block and the offset in it.
        block: u64,
        offset: usize,
        /// The bytes of its listing.
        size: u64,
    },
    File {
        blocks_start: u64,
        size: u64,
        fragment: u32,
        fragment_offset: u64,
        /// Where its list of block sizes is: the inode's place, the bytes
        /// before the list, and how many sizes there are.
        place: (u64, usize),
        before: usize,
        count: u64,
    },
    Other,
}

struct Inode {
    kind: Kind,
    mode: u32,
    mtime: i64,
}

impl Squash {
    fn u16(&self, d: &[u8], at: usize) -> u16 {
        if self.be { be16(d, at) } else { le16(d, at) }
    }

    fn u32(&self, d: &[u8], at: usize) -> u32 {
        if self.be { be32(d, at) } else { le32(d, at) }
    }

    fn u64(&self, d: &[u8], at: usize) -> u64 {
        if self.be { be64(d, at) } else { le64(d, at) }
    }

    /// `src` decompressed with the image's compression, to at most `max` bytes.
    fn unpack(&self, src: &[u8], max: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let limit = u64::try_from(max).ok()?.checked_add(1)?;
        match self.compression {
            1 => {
                crate::inflate::zlib_body(src)?
                    .take(limit)
                    .read_to_end(&mut out)
                    .ok()?;
            }
            2 => {
                let stream = lzma_rust2::LzmaStream::new_mem_limit(128 * 1024, None);
                super::lzma::SansIo::new(src, stream)
                    .take(limit)
                    .read_to_end(&mut out)
                    .ok()?;
            }
            3 => out = super::lzo::decompress(src, max).ok()?,
            4 => {
                super::xz::XzReader::new(src)
                    .take(limit)
                    .read_to_end(&mut out)
                    .ok()?;
            }
            5 => super::lz4::block(src, &mut out, max).ok()?,
            6 => {
                super::zstd::ZstdReader::new(src)
                    .take(limit)
                    .read_to_end(&mut out)
                    .ok()?;
            }
            _ => return None,
        }
        (out.len() <= max).then_some(out)
    }

    /// The metadata block at `at`, and where the one after it is.
    fn meta_block(&mut self, v: &mut Vol, at: u64) -> Option<(Rc<Vec<u8>>, u64)> {
        if let Some((data, next)) = self.cache.get(&at) {
            return Some((Rc::clone(data), *next));
        }
        let head = v.at(at, 2)?;
        let header = self.u16(&head, 0);
        let size = usize::from(header & 0x7FFF);
        if size == 0 || size > META {
            return None;
        }
        let raw = v.at(at.checked_add(2)?, size)?;
        let data = if header & 0x8000 != 0 {
            raw
        } else {
            self.unpack(&raw, META)?
        };
        let next = at.checked_add(2)?.checked_add(size as u64)?;
        if self.cache.len() >= CACHED {
            self.cache.clear();
        }
        let data = Rc::new(data);
        self.cache.insert(at, (Rc::clone(&data), next));
        Some((data, next))
    }

    /// `n` bytes of a table that starts at `table`, from the offset `inner` of
    /// the metadata block that is `block` bytes into it, going on into the
    /// blocks after.
    fn meta_read(
        &mut self,
        v: &mut Vol,
        table: u64,
        block: u64,
        inner: usize,
        n: usize,
    ) -> Option<Vec<u8>> {
        let mut at = table.checked_add(block)?;
        let mut inner = inner;
        let mut out: Vec<u8> = Vec::new();
        while out.len() < n {
            let (data, next) = self.meta_block(v, at)?;
            let left = data.len().checked_sub(inner)?;
            let take = left.min(n.saturating_sub(out.len()));
            if take == 0 {
                return None;
            }
            out.extend_from_slice(data.get(inner..inner.checked_add(take)?)?);
            inner = 0;
            at = next;
        }
        Some(out)
    }

    /// The inode at a reference: the block of the inode table it starts in
    /// (above 16 bits) and the offset in it.
    fn inode(&mut self, v: &mut Vol, reference: u64) -> Option<Inode> {
        let (block, inner) = (reference >> 16, usize::from(reference as u16));
        let h = self.meta_read(v, self.inode_table, block, inner, 16)?;
        let (ty, mode, mtime) = (self.u16(&h, 0), u32::from(self.u16(&h, 2)), self.u32(&h, 8));
        let fixed = match ty {
            1 => 32,
            8 => 40,
            2 => 32,
            9 => 56,
            _ => 16,
        };
        let b = self.meta_read(v, self.inode_table, block, inner, fixed)?;
        let kind = match ty {
            1 => Kind::Dir {
                block: u64::from(self.u32(&b, 16)),
                offset: usize::from(self.u16(&b, 26)),
                size: u64::from(self.u16(&b, 24)),
            },
            8 => Kind::Dir {
                block: u64::from(self.u32(&b, 24)),
                offset: usize::from(self.u16(&b, 34)),
                size: u64::from(self.u32(&b, 20)),
            },
            2 | 9 => {
                let (blocks_start, size, fragment, fragment_offset) = if ty == 2 {
                    (
                        u64::from(self.u32(&b, 16)),
                        u64::from(self.u32(&b, 28)),
                        self.u32(&b, 20),
                        u64::from(self.u32(&b, 24)),
                    )
                } else {
                    (
                        self.u64(&b, 16),
                        self.u64(&b, 24),
                        self.u32(&b, 44),
                        u64::from(self.u32(&b, 48)),
                    )
                };
                // A tail in a fragment is not a block of the list.
                let count = if fragment == NO_FRAGMENT {
                    size.div_ceil(self.block_size)
                } else {
                    size.checked_div(self.block_size)?
                };
                Kind::File {
                    blocks_start,
                    size,
                    fragment,
                    fragment_offset,
                    place: (block, inner),
                    before: fixed,
                    count,
                }
            }
            _ => Kind::Other,
        };
        // The type in `mode` is the one that counts: the inode type says the
        // layout, and a directory may be stored in the extended one.
        let ftype = match ty {
            1 | 8 => S_IFDIR,
            2 | 9 => S_IFREG,
            _ => 0,
        };
        Some(Inode {
            kind,
            mode: (mode & 0o7777) | ftype,
            mtime: i64::from(mtime),
        })
    }

    /// The entries of a directory: name, type and inode reference. The flag is
    /// false where the listing is damaged.
    fn entries(
        &mut self,
        v: &mut Vol,
        block: u64,
        offset: usize,
        size: u64,
        left: &mut u64,
        limit: usize,
    ) -> (Vec<(String, u16, u64)>, bool) {
        let mut out = Vec::new();
        // The listing is three bytes longer than what is in it.
        let want = size.saturating_sub(3);
        if want > MAX_LISTING || want > *left {
            return (out, false);
        }
        *left = left.saturating_sub(want);
        let Some(list) = self.meta_read(
            v,
            self.dir_table,
            block,
            offset,
            crate::bytes::to_usize(want),
        ) else {
            return (out, false);
        };
        let mut at = 0usize;
        while at < list.len() {
            let Some(h) = crate::bytes::at(&list, at, 12) else {
                return (out, false);
            };
            // The entries of one inode block: one fewer than they are, the
            // block, and the number the others are relative to.
            let count = u64::from(self.u32(h, 0)).saturating_add(1);
            let start = u64::from(self.u32(h, 4));
            at = at.saturating_add(12);
            for _ in 0..count {
                let Some(e) = crate::bytes::at(&list, at, 8) else {
                    return (out, false);
                };
                let (inner, ty) = (u64::from(self.u16(e, 0)), self.u16(e, 4));
                let name_len = usize::from(self.u16(e, 6)).saturating_add(1);
                let Some(name) = crate::bytes::at(&list, at.saturating_add(8), name_len) else {
                    return (out, false);
                };
                at = at.saturating_add(8).saturating_add(name_len);
                if out.len() >= limit {
                    return (out, true);
                }
                out.push((
                    String::from_utf8_lossy(name).into_owned(),
                    ty,
                    start.saturating_mul(1 << 16).saturating_add(inner),
                ));
            }
        }
        (out, true)
    }

    /// Where fragment `n` is: its place and its size field.
    fn fragment_place(&mut self, v: &mut Vol, n: u32) -> Option<(u64, u32)> {
        if n >= self.fragments {
            return None;
        }
        let index = u64::from(n.checked_div(512)?);
        let loc = self.u64(
            &v.at(self.frag_table.checked_add(index.checked_mul(8)?)?, 8)?,
            0,
        );
        let slot = usize::try_from(n.checked_rem(512)?).ok()?;
        // A block of the table is a block with no inner offset: it begins at its
        // own place, not at one counted from a table.
        let (data, _) = self.meta_block(v, loc)?;
        let e = crate::bytes::at(&data, slot.checked_mul(16)?, 16)?;
        Some((self.u64(e, 0), self.u32(e, 8)))
    }

    /// The decompressed block of fragments `n`.
    fn fragment_block(&mut self, v: &mut Vol, n: u32) -> Option<Rc<Vec<u8>>> {
        if let Some((m, data)) = &self.fragment
            && *m == n
        {
            return Some(Rc::clone(data));
        }
        let (start, field) = self.fragment_place(v, n)?;
        let data = Rc::new(self.data_block(v, start, field)?);
        self.fragment = Some((n, Rc::clone(&data)));
        Some(data)
    }

    /// A block of data at `at`, as its size field says it is stored.
    fn data_block(&mut self, v: &mut Vol, at: u64, field: u32) -> Option<Vec<u8>> {
        let size = usize::try_from(field & 0x00FF_FFFF).ok()?;
        let raw = v.at(at, size)?;
        if field & 0x0100_0000 != 0 {
            return Some(raw);
        }
        self.unpack(&raw, crate::bytes::to_usize(self.block_size))
    }

    /// The bytes of a file: held when they are at most `cap`, else read as
    /// they go.
    fn file<'a>(&'a mut self, v: &'a mut Vol<'_>, kind: &Kind, cap: u64) -> Got<'a> {
        let Kind::File {
            blocks_start,
            size,
            fragment,
            fragment_offset,
            place,
            before,
            count,
        } = kind
        else {
            return Got::Why("not a file");
        };
        if *size == 0 {
            return Got::Whole(Vec::new());
        }
        if *count > MAX_BLOCKS {
            return Got::Why("SquashFS file with more blocks than are followed");
        }
        let n = crate::bytes::to_usize(*count);
        let list = self.meta_read(
            v,
            self.inode_table,
            place.0,
            place.1,
            before.saturating_add(n.saturating_mul(4)),
        );
        let Some(list) = list else {
            return Got::Why("SquashFS file whose list of blocks is unreadable");
        };
        let bs = crate::bytes::to_usize(self.block_size);
        let fill = Blocks {
            fs: self,
            list,
            before: *before,
            n,
            i: 0,
            at: *blocks_start,
            bs,
            total: crate::bytes::to_usize(*size),
            given: 0,
            fragment: *fragment,
            fragment_offset: *fragment_offset,
            tail: false,
        };
        read_file(v, fill, *size, cap)
    }
}

/// The blocks of a file, then its tail in a fragment, read and decompressed as
/// they are wanted.
struct Blocks<'a> {
    fs: &'a mut Squash,
    /// The inode's bytes: what comes before the list of blocks, and the list.
    list: Vec<u8>,
    before: usize,
    n: usize,
    /// The next block, and where it is stored.
    i: usize,
    at: u64,
    bs: usize,
    total: usize,
    /// How many bytes of the file have been given.
    given: usize,
    fragment: u32,
    fragment_offset: u64,
    /// The tail has been given.
    tail: bool,
}

impl Fill for Blocks<'_> {
    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        if self.i < self.n {
            let field = self.fs.u32(
                &self.list,
                self.before.saturating_add(self.i.saturating_mul(4)),
            );
            // The last block is what is left, if the tail is not in a fragment.
            let want = self.bs.min(self.total.saturating_sub(self.given));
            let stored = u64::from(field & 0x00FF_FFFF);
            if stored == 0 {
                out.resize(out.len().saturating_add(want), 0);
            } else {
                match self.fs.data_block(v, self.at, field) {
                    Some(mut b) => {
                        b.resize(want, 0);
                        out.extend_from_slice(&b);
                    }
                    None => return Step::Broken,
                }
                self.at = self.at.saturating_add(stored);
            }
            self.given = self.given.saturating_add(want);
            self.i = self.i.saturating_add(1);
            return Step::More;
        }
        if self.fragment == NO_FRAGMENT || self.tail {
            return Step::End;
        }
        let tail = self.total.saturating_sub(self.given);
        let from = crate::bytes::to_usize(self.fragment_offset);
        let part = self
            .fs
            .fragment_block(v, self.fragment)
            .and_then(|b| crate::bytes::at(&b, from, tail).map(<[u8]>::to_vec));
        match part {
            Some(p) => {
                self.given = self.given.saturating_add(p.len());
                out.extend_from_slice(&p);
                self.tail = true;
                Step::More
            }
            None => Step::Broken,
        }
    }
}

/// The image's superblock, or `None` where it describes none that is read.
fn open(v: &mut Vol) -> Option<Squash> {
    let b = v.at(0, 96)?;
    let be = b.starts_with(b"sqsh");
    let mut s = Squash {
        be,
        block_size: 0,
        compression: 0,
        fragments: 0,
        root: 0,
        inode_table: 0,
        dir_table: 0,
        frag_table: 0,
        cache: HashMap::new(),
        fragment: None,
    };
    let (block_size, log) = (u64::from(s.u32(&b, 12)), s.u16(&b, 22));
    if s.u16(&b, 28) != 4
        || !(4096..=1 << 20).contains(&block_size)
        || !block_size.is_power_of_two()
        || block_size != 1u64.checked_shl(u32::from(log))?
    {
        return None;
    }
    s.block_size = block_size;
    s.compression = s.u16(&b, 20);
    s.fragments = s.u32(&b, 16);
    s.root = s.u64(&b, 32);
    s.inode_table = s.u64(&b, 64);
    s.dir_table = s.u64(&b, 72);
    s.frag_table = s.u64(&b, 80);
    // The root is a directory of the inode table.
    let root = s.inode(v, s.root)?;
    matches!(root.kind, Kind::Dir { .. }).then_some(s)
}

/// Walk a SquashFS image given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the SquashFS image `disk`, which is `len` bytes long, handing each
/// file to `visit`.
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
    let head = match v.at(0, 96) {
        Some(h) if is_squashfs(&h) => h,
        _ => return Ok(None),
    };
    let be = head.starts_with(b"sqsh");
    let version = if be { be16(&head, 28) } else { le16(&head, 28) };
    if version != 4 {
        budget.count_entry()?;
        let note = Entry::unsupported(
            "<squashfs-filesystem>".to_string(),
            len,
            false,
            "SquashFS before version 4 is not read",
        );
        return Ok(visit(Found::Held(note), budget));
    }
    let Some(mut fs) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "squashfs open: the superblock or the root directory is unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    // The directory listings of an image are all of its directory table.
    let mut left = fs
        .frag_table
        .saturating_sub(fs.dir_table)
        .saturating_mul(4096);
    let mut damaged = false;
    // A listing is a place and a length: an empty one is where the next begins.
    let mut seen: HashSet<(u64, usize, u64)> = HashSet::new();
    let mut stack = Vec::new();
    if let Some(Inode {
        kind: Kind::Dir {
            block,
            offset,
            size,
        },
        ..
    }) = fs.inode(&mut v, fs.root)
    {
        seen.insert((block, offset, size));
        stack.push((block, offset, size, String::new(), 0usize));
    }
    while let Some((block, offset, size, prefix, depth)) = stack.pop() {
        let (list, intact) = fs.entries(&mut v, block, offset, size, &mut left, limit);
        damaged |= !intact;
        let mut below = Vec::new();
        for (name, _, reference) in list {
            budget.count_entry()?;
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let Some(inode) = fs.inode(&mut v, reference) else {
                damaged = true;
                continue;
            };
            match inode.kind {
                Kind::Dir {
                    block,
                    offset,
                    size,
                } => {
                    if depth >= MAX_DEPTH {
                        damaged = true;
                    } else if seen.insert((block, offset, size)) {
                        below.push((block, offset, size, path, depth.saturating_add(1)));
                    }
                }
                Kind::File { .. } => {
                    let attrs = Attrs {
                        mode: Some(inode.mode),
                        mtime: Some(Mtime::Unix(inode.mtime)),
                    };
                    if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                        fs.file(&mut v, &inode.kind, cap)
                    })? {
                        return Ok(Some(r));
                    }
                }
                // A link or a node holds no file's bytes.
                Kind::Other => {}
            }
        }
        stack.extend(below.into_iter().rev());
    }
    if damaged {
        return Err(LimitHit::corrupt(
            "squashfs walk: the image is damaged; the files before the damage were scanned".into(),
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

    /// A file or a directory to put in an image.
    enum N {
        File(Vec<u8>),
        Dir(Vec<(&'static str, N)>),
    }

    /// An image written the way `mksquashfs` lays one out, nothing compressed:
    /// the superblock, the data blocks, the inode table, the directory table and
    /// the fragment table. One directory header to each entry.
    struct Img {
        be: bool,
        data: Vec<u8>,
        inodes: Vec<u8>,
        dirs: Vec<u8>,
        /// (place in the data, size field) of each fragment block.
        fragments: Vec<(usize, u32)>,
        count: u32,
    }

    impl Img {
        fn put16(&self, v: &mut Vec<u8>, x: u16) {
            v.extend_from_slice(&if self.be {
                x.to_be_bytes()
            } else {
                x.to_le_bytes()
            });
        }
        fn put32(&self, v: &mut Vec<u8>, x: u32) {
            v.extend_from_slice(&if self.be {
                x.to_be_bytes()
            } else {
                x.to_le_bytes()
            });
        }
        fn put64(&self, v: &mut Vec<u8>, x: u64) {
            v.extend_from_slice(&if self.be {
                x.to_be_bytes()
            } else {
                x.to_le_bytes()
            });
        }

        /// A table as metadata blocks, none compressed.
        fn meta(&self, table: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            for chunk in table.chunks(META) {
                self.put16(&mut out, 0x8000 | chunk.len() as u16);
                out.extend_from_slice(chunk);
            }
            out
        }

        /// The place of byte `pos` of a table in its metadata blocks.
        fn place(pos: usize) -> (u64, u16) {
            ((pos / META * (META + 2)) as u64, (pos % META) as u16)
        }

        fn inode_header(&mut self, ty: u16, mode: u16) {
            let mut h = Vec::new();
            self.put16(&mut h, ty);
            self.put16(&mut h, mode);
            self.put16(&mut h, 0);
            self.put16(&mut h, 0);
            self.put32(&mut h, 1_700_000_000);
            self.count += 1;
            let n = self.count;
            self.put32(&mut h, n);
            self.inodes.extend_from_slice(&h);
        }

        /// Write `n`; its inode reference and its type.
        fn node(&mut self, n: &N, tail_in_fragment: bool) -> (u64, u16) {
            match n {
                N::File(bytes) => {
                    let start = self.data.len();
                    let full = bytes.len() / BS;
                    let tail = bytes.len() % BS;
                    let (mut sizes, mut fragment, mut offset) = (Vec::new(), NO_FRAGMENT, 0u32);
                    let blocks = if tail > 0 && !tail_in_fragment {
                        full + 1
                    } else {
                        full
                    };
                    for i in 0..blocks {
                        let chunk = &bytes[i * BS..bytes.len().min((i + 1) * BS)];
                        if chunk.iter().all(|&b| b == 0) {
                            // A sparse block is stored as nothing.
                            sizes.push(0u32);
                        } else {
                            sizes.push(chunk.len() as u32 | 0x0100_0000);
                            self.data.extend_from_slice(chunk);
                        }
                    }
                    if tail > 0 && tail_in_fragment {
                        // The tails share a fragment block per file here.
                        fragment = self.fragments.len() as u32;
                        offset = 0;
                        let at = self.data.len();
                        self.data.extend_from_slice(&bytes[full * BS..]);
                        self.fragments.push((at, tail as u32 | 0x0100_0000));
                    }
                    let (block, inner) = Img::place(self.inodes.len());
                    self.inode_header(2, 0o100644);
                    let mut b = Vec::new();
                    self.put32(&mut b, (96 + start) as u32);
                    self.put32(&mut b, fragment);
                    self.put32(&mut b, offset);
                    self.put32(&mut b, bytes.len() as u32);
                    for s in sizes {
                        self.put32(&mut b, s);
                    }
                    self.inodes.extend_from_slice(&b);
                    (block << 16 | u64::from(inner), 2)
                }
                N::Dir(entries) => {
                    let mut kids: Vec<_> = entries
                        .iter()
                        .map(|(name, n)| (*name, self.node(n, tail_in_fragment)))
                        .collect();
                    kids.sort_by_key(|k| k.0);
                    let (dblock, doffset) = Img::place(self.dirs.len());
                    let mut list = Vec::new();
                    for (name, (reference, ty)) in &kids {
                        self.put32(&mut list, 0);
                        self.put32(&mut list, (reference >> 16) as u32);
                        self.put32(&mut list, 1);
                        self.put16(&mut list, (reference & 0xFFFF) as u16);
                        self.put16(&mut list, 0);
                        self.put16(&mut list, *ty);
                        self.put16(&mut list, (name.len() - 1) as u16);
                        list.extend_from_slice(name.as_bytes());
                    }
                    self.dirs.extend_from_slice(&list);
                    let (block, inner) = Img::place(self.inodes.len());
                    self.inode_header(1, 0o040755);
                    let mut b = Vec::new();
                    self.put32(&mut b, dblock as u32);
                    self.put32(&mut b, 2);
                    self.put16(&mut b, (list.len() + 3) as u16);
                    self.put16(&mut b, doffset);
                    self.put32(&mut b, 1);
                    self.inodes.extend_from_slice(&b);
                    (block << 16 | u64::from(inner), 1)
                }
            }
        }

        /// The image of `root`.
        fn build(be: bool, root: &N, tail_in_fragment: bool) -> Vec<u8> {
            let mut img = Img {
                be,
                data: Vec::new(),
                inodes: Vec::new(),
                dirs: Vec::new(),
                fragments: Vec::new(),
                count: 0,
            };
            let (root_ref, _) = img.node(root, tail_in_fragment);
            let inode_table = 96 + img.data.len();
            let inodes = img.meta(&img.inodes);
            let dir_table = inode_table + inodes.len();
            let dirs = img.meta(&img.dirs);
            // The fragment table: a metadata block of 16-byte entries, and the
            // list of the places of those.
            let mut entries = Vec::new();
            for &(at, size) in &img.fragments {
                img.put64(&mut entries, (96 + at) as u64);
                img.put32(&mut entries, size);
                img.put32(&mut entries, 0);
            }
            let frag_block = img.meta(&entries);
            let frag_block_at = dir_table + dirs.len();
            let mut index = Vec::new();
            if !img.fragments.is_empty() {
                img.put64(&mut index, frag_block_at as u64);
            }
            let frag_table = frag_block_at + frag_block.len();
            let total = frag_table + index.len();
            let mut sb = Vec::new();
            sb.extend_from_slice(if be { b"sqsh" } else { b"hsqs" });
            img.put32(&mut sb, img.count);
            img.put32(&mut sb, 1_700_000_000);
            img.put32(&mut sb, BS as u32);
            img.put32(&mut sb, img.fragments.len() as u32);
            img.put16(&mut sb, 1);
            img.put16(&mut sb, 12);
            img.put16(&mut sb, 0xB);
            img.put16(&mut sb, 0);
            img.put16(&mut sb, 4);
            img.put16(&mut sb, 0);
            img.put64(&mut sb, root_ref);
            img.put64(&mut sb, total as u64);
            img.put64(&mut sb, 0);
            img.put64(&mut sb, u64::MAX);
            img.put64(&mut sb, inode_table as u64);
            img.put64(&mut sb, dir_table as u64);
            img.put64(&mut sb, frag_table as u64);
            img.put64(&mut sb, u64::MAX);
            assert_eq!(sb.len(), 96);
            [sb, img.data, inodes, dirs, frag_block, index].concat()
        }
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

    fn pat(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
            .collect()
    }

    fn tree() -> N {
        let mut sparse = pat(BS, 1);
        sparse.extend(vec![0u8; BS]);
        sparse.extend(pat(100, 2));
        N::Dir(vec![
            ("a.txt", N::File(b"hello".to_vec())),
            ("empty", N::File(Vec::new())),
            ("big", N::File(pat(3 * BS + 77, 3))),
            ("sparse", N::File(sparse)),
            (
                "sub",
                N::Dir(vec![
                    ("deeper", N::Dir(vec![("x.bin", N::File(pat(BS, 4)))])),
                    ("y.bin", N::File(pat(10, 5))),
                ]),
            ),
        ])
    }

    fn want() -> Vec<(String, Vec<u8>)> {
        let mut sparse = pat(BS, 1);
        sparse.extend(vec![0u8; BS]);
        sparse.extend(pat(100, 2));
        vec![
            ("a.txt".into(), b"hello".to_vec()),
            ("big".into(), pat(3 * BS + 77, 3)),
            ("empty".into(), Vec::new()),
            ("sparse".into(), sparse),
            ("sub/deeper/x.bin".into(), pat(BS, 4)),
            ("sub/y.bin".into(), pat(10, 5)),
        ]
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
    fn the_files_come_out_of_an_image_of_either_byte_order_with_tails_and_holes() {
        for be in [false, true] {
            for tails in [false, true] {
                let img = Img::build(be, &tree(), tails);
                let (e, end) = walked(&img, Limits::default());
                end.unwrap_or_else(|h| panic!("be {be} tails {tails}: {h:?}"));
                assert_eq!(sorted(e), want(), "be {be} tails {tails}");
            }
        }
    }

    #[test]
    fn a_directory_that_is_empty_does_not_hide_the_one_after_it() {
        let root = N::Dir(vec![
            ("a", N::Dir(vec![])),
            ("b", N::Dir(vec![("f", N::File(b"in b".to_vec()))])),
        ]);
        let (e, end) = walked(&Img::build(false, &root, false), Limits::default());
        end.unwrap();
        assert_eq!(sorted(e), [("b/f".to_string(), b"in b".to_vec())]);
    }

    #[test]
    fn a_directory_that_lists_itself_is_walked_once() {
        let mut img = Img::build(false, &tree(), false);
        // The root's listing is the last directory table's first run; make the
        // entry named `sub` (a directory) point at the root's inode instead.
        let root_ref = u64::from_le_bytes(img[32..40].try_into().unwrap());
        let sub = img
            .windows(3)
            .position(|w| w == b"sub")
            .filter(|&p| p > 8)
            .unwrap();
        // The entry: offset u16, delta i16, type u16, name size u16, the name;
        // the header before it has the inode block.
        let header = sub - 8 - 12;
        img[header + 4..header + 8].copy_from_slice(&((root_ref >> 16) as u32).to_le_bytes());
        img[sub - 8..sub - 6].copy_from_slice(&((root_ref & 0xFFFF) as u16).to_le_bytes());
        let (e, end) = walked(&img, Limits::default());
        end.unwrap();
        let names: Vec<_> = e.iter().map(|m| m.0.as_str()).collect();
        assert_eq!(
            names.iter().filter(|n| n.ends_with("a.txt")).count(),
            1,
            "{names:?}"
        );
    }

    #[test]
    fn a_file_whose_blocks_or_fragment_are_not_there_is_reported_with_what_there_is() {
        // The fragment index past the fragments there are.
        let mut img = Img::build(false, &N::Dir(vec![("f", N::File(pat(BS + 5, 9)))]), true);
        let inode_table = u64::from_le_bytes(img[64..72].try_into().unwrap()) as usize;
        // The file inode follows the header (16 bytes) after the block (2).
        let at = inode_table + 2 + 16 + 4;
        img[at..at + 4].copy_from_slice(&7u32.to_le_bytes());
        let (e, end) = walked(&img, Limits::default());
        end.unwrap();
        assert_eq!(e[0].2, Some("file could not be read from the volume"));
        assert_eq!(e[0].1.len(), BS);

        // A block that runs past the image.
        let mut img = Img::build(false, &N::Dir(vec![("f", N::File(pat(2 * BS, 9)))]), false);
        let at = inode_table_of(&img) + 2 + 16 + 16;
        img[at..at + 4].copy_from_slice(&(0x00FF_FFFFu32 | 0x0100_0000).to_le_bytes());
        let (e, _) = walked(&img, Limits::default());
        assert_eq!(e[0].2, Some("file could not be read from the volume"));
    }

    fn inode_table_of(img: &[u8]) -> usize {
        u64::from_le_bytes(img[64..72].try_into().unwrap()) as usize
    }

    #[test]
    fn what_is_not_a_superblock_is_not_an_image() {
        let good = Img::build(false, &tree(), false);
        // What is written, and where.
        let edits: [(&str, usize, &[u8]); 5] = [
            ("a block size of 3000", 12, &3000u32.to_le_bytes()),
            ("a block size that is not its log", 22, &[13, 0]),
            ("a root inode in no block", 32, &[0xFF; 8]),
            ("an inode table past the image", 64, &[0xFF; 8]),
            ("a root that is a file", 32, &[0, 0, 0, 0, 0, 0, 0, 0]),
        ];
        for (what, at, bytes) in edits {
            let mut img = good.clone();
            img[at..at + bytes.len()].copy_from_slice(bytes);
            let (e, end) = walked(&img, Limits::default());
            // A root that is a file: the first inode written is a file.
            assert!(
                end.as_ref().is_err_and(|h| h.is_corrupt()) || e.is_empty(),
                "{what}"
            );
        }
        // Version 3 is reported and not read.
        let mut v3 = good.clone();
        v3[28..30].copy_from_slice(&3u16.to_le_bytes());
        let (e, end) = walked(&v3, Limits::default());
        end.unwrap();
        assert_eq!(e[0].2, Some("SquashFS before version 4 is not read"));
    }

    #[test]
    fn the_entry_past_the_member_limit_is_counted_and_stops_the_walk() {
        let root = N::Dir(vec![
            ("a", N::File(b"a".to_vec())),
            ("b", N::File(b"b".to_vec())),
            ("c", N::File(b"c".to_vec())),
        ]);
        let img = Img::build(false, &root, false);
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
    fn files_over_the_buffer_limit_are_read_as_they_go_in_either_byte_order() {
        for be in [false, true] {
            for tails in [false, true] {
                let img = Img::build(be, &tree(), tails);
                let len = img.len() as u64;
                let mut budget = Budget::new(Limits {
                    max_buffer_bytes: 100,
                    ..Limits::default()
                });
                let (e, end) =
                    collected(|emit| walk_volume(Cursor::new(&img[..]), len, &mut budget, emit));
                end.unwrap_or_else(|h| panic!("be {be} tails {tails}: {h:?}"));
                let mut got: Vec<(String, Vec<u8>)> = e
                    .iter()
                    .map(|(m, _)| (m.name.clone(), m.data.clone()))
                    .collect();
                got.sort_by(|a, b| a.0.cmp(&b.0));
                assert_eq!(got, want(), "be {be} tails {tails}");
                for (m, streamed) in &e {
                    assert_eq!(m.unsupported, None, "{}", m.name);
                    assert_eq!(*streamed, m.data.len() > 100, "{}", m.name);
                }
                assert!(e.iter().any(|(_, streamed)| *streamed));
            }
        }
    }
}
