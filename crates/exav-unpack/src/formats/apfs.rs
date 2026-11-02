//! APFS: the files of a container, read where they lie.
//!
//! The container is a `Read + Seek`, read where the walk goes: its
//! superblock, the object maps, the nodes of each volume's file-system tree,
//! and each file's extents. Only a file is ever held, bounded by the buffer
//! limit.
//!
//! A scanner wants every file's bytes, not a navigable tree, so the file-system
//! tree is read once, in key order, for its directory records, and the paths
//! are rebuilt from those. Each file is then looked up by its id for the
//! three things it has: the inode (size, flags), the attributes
//! (`com.apple.decmpfs`, read by `formats/decmpfs`) and the extents.
//!
//! ```text
//! block 0, checkpoint area      container superblock: block size, the volumes'
//!                               ids, the container's object map
//!   object map                  B-tree: virtual object id -> block
//!   volume superblock           the volume's object map and tree root ids
//!     file-system tree          B-tree, ordered by (object id, record type):
//!       inode (3)               mode, flags, size
//!       attribute (4)           extended attribute, or the stream holding it
//!       file extent (8)         logical offset -> blocks; none: a hole
//!       directory record (9)    (parent id, name) -> the object's id and kind
//! ```
//!
//! All fields are little-endian, and every object begins with the Fletcher-64
//! checksum of its block. Like every format's, it is not checked unless the
//! budget asks for that (`checksums`), except to choose between the container's
//! superblocks. Implemented from Apple's published reference.
//!
//! Every volume of the container is walked, under its name when there are
//! several. A volume that is encrypted is reported, not read. A symbolic link
//! is not read.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use super::decmpfs;
use super::vol::{
    Attrs as VolAttrs, Emit, Found, Got, Next, Piece, Pieces, Plan, Vol, hand, le16, le32, le64,
    read_file,
};
use crate::{Budget, Entry, LimitHit};

/// "NXSB" and "APSB", little-endian, 32 bytes into their blocks.
const NX_MAGIC: u32 = 0x4253_584E;
const APSB_MAGIC: u32 = 0x4253_5041;

/// Record types of the file-system tree.
const J_INODE: u8 = 3;
const J_XATTR: u8 = 4;
const J_FILE_EXTENT: u8 = 8;
const J_DREC: u8 = 9;

/// The id of the root directory.
const ROOT: u64 = 2;

/// Directory record kinds.
const DT_DIR: u16 = 4;
const DT_LNK: u16 = 10;

/// `APFS_FS_UNENCRYPTED`, a volume flag.
const FS_UNENCRYPTED: u64 = 1;

/// An inode flag: the size of the file before compression is recorded.
const HAS_UNCOMPRESSED_SIZE: u64 = 0x4_0000;

/// A tree is no deeper than this: a node's level counts down to a leaf's 0.
const MAX_LEVEL: u16 = 16;

/// The most records one walk of a tree visits.
const MAX_RECORDS: u64 = 1 << 26;

/// The most mappings of an object map that are kept.
const MAX_OMAP: usize = 1 << 20;

/// The most extents of one file that are followed.
const MAX_EXTENTS: usize = 1 << 20;

/// The most blocks of the checkpoint area that are searched for the newest
/// superblock.
const MAX_CHECKPOINT_BLOCKS: u64 = 1024;

/// The most folders a path passes through.
const MAX_PATH_DEPTH: usize = 256;

/// The most blocks kept after they are read.
const CACHE: usize = 256;

/// The most an attribute held in a stream is, bytes.
const ATTR_MAX: u64 = 1 << 16;

/// The Fletcher-64 checksum of an object's block, from its ninth byte on.
fn fletcher64(data: &[u8]) -> u64 {
    const M: u64 = 0xFFFF_FFFF;
    let (mut s1, mut s2) = (0u64, 0u64);
    for c in data.as_chunks::<4>().0 {
        s1 = s1.saturating_add(u64::from(u32::from_le_bytes(*c))) % M;
        s2 = s2.saturating_add(s1) % M;
    }
    let c1 = M.saturating_sub(s1.saturating_add(s2) % M);
    let c2 = M.saturating_sub(s1.saturating_add(c1) % M);
    c2 << 32 | c1
}

/// A structure that is not what it must be, or cannot be read.
struct Bad;

type Res<T> = Result<T, Bad>;

/// Whether a block carries the checksum of the rest of it.
fn sum_holds(b: &[u8]) -> bool {
    b.get(8..)
        .is_some_and(|rest| le64(b, 0) == fletcher64(rest))
}

/// The container's blocks.
struct Fs<'a, 'd> {
    v: &'a mut Vol<'d>,
    block: u64,
    cache: HashMap<u64, Vec<u8>>,
    /// Whether a block whose checksum does not hold is refused. It is not, as
    /// with every format: a checksum that is wrong must not keep a file from
    /// being scanned.
    strict: bool,
}

impl Fs<'_, '_> {
    /// Block `n`, if it is in the volume, whatever its checksum.
    fn raw(&mut self, n: u64) -> Option<Vec<u8>> {
        self.v.at(
            n.checked_mul(self.block)?,
            crate::bytes::to_usize(self.block),
        )
    }

    /// Block `n`, if it is in the volume and, when checksums are checked, its
    /// checksum holds.
    fn read(&mut self, n: u64) -> Option<Vec<u8>> {
        let b = self.raw(n)?;
        (!self.strict || sum_holds(&b)).then_some(b)
    }

    /// [`Self::read`], kept for the next time: the top of a tree is read for
    /// every lookup.
    fn block(&mut self, n: u64) -> Option<Vec<u8>> {
        if let Some(b) = self.cache.get(&n) {
            return Some(b.clone());
        }
        let b = self.read(n)?;
        if self.cache.len() >= CACHE {
            self.cache.clear();
        }
        self.cache.insert(n, b.clone());
        Some(b)
    }
}

const ROOT_NODE: u16 = 1;
const LEAF_NODE: u16 = 2;
const FIXED_NODE: u16 = 4;

/// A node of a B-tree.
struct Node {
    b: Vec<u8>,
    flags: u16,
    level: u16,
    count: usize,
    /// Where the table of contents, the keys and the values begin and end.
    toc: usize,
    keys: usize,
    vals: usize,
}

impl Node {
    fn parse(b: Vec<u8>) -> Option<Node> {
        let flags = le16(&b, 32);
        let count = crate::bytes::to_usize(u64::from(le32(&b, 36)));
        let toc = 56usize.checked_add(usize::from(le16(&b, 40)))?;
        let keys = toc.checked_add(usize::from(le16(&b, 42)))?;
        // The root ends in the tree's description, which the values stop before.
        let vals = match flags & ROOT_NODE != 0 {
            true => b.len().checked_sub(40)?,
            false => b.len(),
        };
        let entry = if flags & FIXED_NODE != 0 { 4 } else { 8 };
        if toc.checked_add(count.checked_mul(entry)?)? > keys || keys > vals {
            return None;
        }
        Some(Node {
            level: le16(&b, 34),
            flags,
            count,
            toc,
            keys,
            vals,
            b,
        })
    }

    fn leaf(&self) -> bool {
        self.flags & LEAF_NODE != 0
    }

    /// Record `i`: its key and its value. `fixed` is the sizes of the keys and
    /// values of a tree that has only one size of each.
    fn rec(&self, i: usize, fixed: Option<(usize, usize)>) -> Option<(&[u8], &[u8])> {
        if i >= self.count {
            return None;
        }
        let at = |o: usize| Some(usize::from(le16(&self.b, o)));
        let (key, val) = if self.flags & FIXED_NODE != 0 {
            let (k, v) = fixed?;
            let e = self.toc.checked_add(i.checked_mul(4)?)?;
            ((at(e)?, k), (at(e.checked_add(2)?)?, v))
        } else {
            let e = self.toc.checked_add(i.checked_mul(8)?)?;
            (
                (at(e)?, at(e.checked_add(2)?)?),
                (at(e.checked_add(4)?)?, at(e.checked_add(6)?)?),
            )
        };
        // What a node above the leaves holds is the id of a child.
        let val_len = if self.leaf() { val.1 } else { 8 };
        let val_at = self.vals.checked_sub(val.0).filter(|&s| s >= self.keys)?;
        Some((
            crate::bytes::at(&self.b, self.keys.checked_add(key.0)?, key.1)?,
            crate::bytes::at(&self.b, val_at, val_len)?,
        ))
    }
}

/// What an object map holds: the block of each object id, `None` where the
/// newest mapping is a deletion.
type Omap = HashMap<u64, Option<u64>>;

/// A B-tree, from its root's block.
struct Tree<'o> {
    root: u64,
    fixed: Option<(usize, usize)>,
    /// How the ids of its children become blocks: through an object map, or
    /// not at all (they are blocks).
    omap: Option<&'o Omap>,
}

/// A position in a tree, from which its records follow in order.
struct Cursor {
    /// The nodes from the root to a leaf, and in each the child taken (the
    /// record of a leaf not yet given).
    stack: Vec<(Node, usize)>,
    seen: u64,
}

impl Tree<'_> {
    fn child(&self, fs: &mut Fs, node: &Node, i: usize) -> Res<Node> {
        let (_, id) = node.rec(i, self.fixed).ok_or(Bad)?;
        let id = le64(id, 0);
        let block = match self.omap {
            Some(map) => map.get(&id).copied().flatten().ok_or(Bad)?,
            None => id,
        };
        let child = Node::parse(fs.block(block).ok_or(Bad)?).ok_or(Bad)?;
        let leaf_ok = child.leaf() == (child.level == 0);
        match child.level.checked_add(1) == Some(node.level) && leaf_ok {
            true => Ok(child),
            false => Err(Bad),
        }
    }

    /// The first record whose key `before` does not put before the one wanted,
    /// and those after it. Keys of the nodes above are the least of what is
    /// below them, so the descent takes the last child whose key is before.
    fn seek(&self, fs: &mut Fs, before: &dyn Fn(&[u8]) -> bool) -> Res<Cursor> {
        let mut node = Node::parse(fs.block(self.root).ok_or(Bad)?).ok_or(Bad)?;
        if node.level > MAX_LEVEL || node.leaf() != (node.level == 0) {
            return Err(Bad);
        }
        let mut stack = Vec::new();
        loop {
            let keys = (0..node.count).map(|i| node.rec(i, self.fixed).map(|(k, _)| k));
            if node.leaf() {
                let mut at = node.count;
                for (i, key) in keys.enumerate() {
                    if !before(key.ok_or(Bad)?) {
                        at = i;
                        break;
                    }
                }
                stack.push((node, at));
                return Ok(Cursor { stack, seen: 0 });
            }
            let mut pick = 0;
            for (i, key) in keys.enumerate() {
                if !before(key.ok_or(Bad)?) {
                    break;
                }
                pick = i;
            }
            let child = self.child(fs, &node, pick)?;
            stack.push((node, pick));
            node = child;
        }
    }
}

impl Cursor {
    /// The next record, a copy of its key and of its value.
    fn next(&mut self, fs: &mut Fs, tree: &Tree) -> Res<Option<(Vec<u8>, Vec<u8>)>> {
        loop {
            let Some((node, at)) = self.stack.last_mut() else {
                return Ok(None);
            };
            if !node.leaf() {
                return Err(Bad);
            }
            if *at < node.count {
                let i = *at;
                *at = at.saturating_add(1);
                self.seen = self.seen.saturating_add(1);
                if self.seen > MAX_RECORDS {
                    return Err(Bad);
                }
                let (k, v) = node.rec(i, tree.fixed).ok_or(Bad)?;
                return Ok(Some((k.to_vec(), v.to_vec())));
            }
            // This leaf is done: on to the next child of the nearest node
            // above that has one, and down its first children to a leaf.
            self.stack.pop();
            let mut down = loop {
                let Some((parent, taken)) = self.stack.last_mut() else {
                    return Ok(None);
                };
                *taken = taken.saturating_add(1);
                if *taken < parent.count {
                    break tree.child(fs, parent, *taken)?;
                }
                self.stack.pop();
            };
            while !down.leaf() {
                let first = tree.child(fs, &down, 0)?;
                self.stack.push((down, 0));
                down = first;
            }
            self.stack.push((down, 0));
        }
    }
}

/// The object id and the record type a key of the file-system tree starts with.
fn key_of(key: &[u8]) -> (u64, u8) {
    let packed = le64(key, 0);
    (packed & 0x0FFF_FFFF_FFFF_FFFF, (packed >> 60) as u8)
}

/// The object map at physical block `block`: the block of each object id as of
/// transaction `xid`.
fn load_omap(fs: &mut Fs, block: u64, xid: u64) -> Option<Omap> {
    let object = fs.block(block)?;
    let tree = Tree {
        root: le64(&object, 48),
        fixed: Some((16, 16)),
        omap: None,
    };
    let mut cursor = tree.seek(fs, &|_| false).ok()?;
    // (the newest transaction seen, where it maps the object)
    let mut newest: HashMap<u64, (u64, Option<u64>)> = HashMap::new();
    while let Some((key, val)) = cursor.next(fs, &tree).ok()? {
        let (id, at) = (le64(&key, 0), le64(&key, 8));
        if at > xid || key.len() < 16 || val.len() < 16 {
            continue;
        }
        if newest.len() >= MAX_OMAP && !newest.contains_key(&id) {
            return None;
        }
        // Bit 0 of the flags marks a deleted mapping.
        let to = (le32(&val, 0) & 1 == 0).then(|| le64(&val, 8));
        match newest.get(&id) {
            Some(&(seen, _)) if seen > at => {}
            _ => {
                newest.insert(id, (at, to));
            }
        }
    }
    Some(newest.into_iter().map(|(id, (_, to))| (id, to)).collect())
}

/// An inode, as far as a walk reads it.
struct Inode {
    /// The id its extents are keyed by.
    stream: u64,
    flags: u32,
    size: u64,
}

impl Inode {
    fn parse(val: &[u8]) -> Option<Inode> {
        if val.len() < 92 {
            return None;
        }
        let size = match dstream_size(val.get(92..)?) {
            Some(size) => size,
            None if le64(val, 48) & HAS_UNCOMPRESSED_SIZE != 0 => le64(val, 84),
            None => 0,
        };
        Some(Inode {
            stream: le64(val, 8),
            flags: le32(val, 68),
            size,
        })
    }
}

/// The size of the data stream in an inode's extended fields: a count and a
/// length, an (id, flags, length) triple for each, then their values, each
/// padded to eight bytes. The stream is field 8 and starts with its size.
fn dstream_size(x: &[u8]) -> Option<u64> {
    let count = usize::from(le16(x, 0));
    let mut at = count.checked_mul(4)?.checked_add(4)?;
    for i in 0..count {
        let e = i.checked_mul(4)?.checked_add(4)?;
        let len = usize::from(le16(x, e.checked_add(2)?));
        if *x.get(e)? == 8 && len >= 8 {
            return Some(le64(crate::bytes::at(x, at, 8)?, 0));
        }
        at = at.checked_add(len.checked_add(7)? & !7)?;
    }
    None
}

/// The name in a directory record's key: a length and a hash, or a length
/// alone, then the name and its NUL.
fn drec_name(key: &[u8]) -> Option<String> {
    let hashed = usize::try_from(le32(key, 8) & 0x3FF).ok()?;
    let (len, at) = match key.len() == hashed.checked_add(12)? {
        true => (hashed, 12),
        false => (usize::from(le16(key, 8)), 10),
    };
    let name =
        crate::bytes::at(key, at, len).filter(|n| at.saturating_add(n.len()) == key.len())?;
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    Some(String::from_utf8_lossy(name).into_owned())
}

/// A file named by a directory record.
struct Named {
    id: u64,
    parent: u64,
    name: String,
}

/// A file's extents: (offset in the file, length, first block); a first block
/// of 0 is a hole.
struct Extent {
    at: u64,
    len: u64,
    block: u64,
}

/// What a file's attributes give a walk.
#[derive(Default)]
struct Attrs {
    decmpfs: Option<Vec<u8>>,
    /// The stream that is the resource fork: its id and size.
    fork: Option<(u64, u64)>,
}

/// A volume, mounted.
struct Volume<'o> {
    tree: Tree<'o>,
}

impl Volume<'_> {
    fn inode(&self, fs: &mut Fs, id: u64) -> Res<Inode> {
        let mut c = self.records(fs, id, J_INODE)?;
        match c.next(fs, &self.tree)? {
            Some((k, v)) if key_of(&k) == (id, J_INODE) => Inode::parse(&v).ok_or(Bad),
            _ => Err(Bad),
        }
    }

    /// A cursor at the first record of object `id` of type `ty` (or the first
    /// after).
    fn records(&self, fs: &mut Fs, id: u64, ty: u8) -> Res<Cursor> {
        self.tree.seek(fs, &|k| key_of(k) < (id, ty))
    }

    fn extents(&self, fs: &mut Fs, id: u64) -> Res<Vec<Extent>> {
        let mut c = self.records(fs, id, J_FILE_EXTENT)?;
        let mut out = Vec::new();
        while let Some((k, v)) = c.next(fs, &self.tree)? {
            if key_of(&k) != (id, J_FILE_EXTENT) {
                break;
            }
            if out.len() >= MAX_EXTENTS {
                return Err(Bad);
            }
            // The key: the id and type, then the offset in the file. The
            // value: the length (and flags above 56 bits), the first block,
            // the crypto id.
            out.push(Extent {
                at: le64(&k, 8),
                len: le64(&v, 0) & 0x00FF_FFFF_FFFF_FFFF,
                block: le64(&v, 8),
            });
        }
        Ok(out)
    }

    fn attrs(&self, fs: &mut Fs, id: u64) -> Res<Attrs> {
        let mut c = self.records(fs, id, J_XATTR)?;
        let mut out = Attrs::default();
        while let Some((k, v)) = c.next(fs, &self.tree)? {
            if key_of(&k) != (id, J_XATTR) {
                break;
            }
            // The key: the id and type, a length, the name and its NUL.
            let len = usize::from(le16(&k, 8));
            let name = crate::bytes::at(&k, 10, len).unwrap_or_default();
            let name = name.strip_suffix(&[0]).unwrap_or(name);
            // The value: flags, a length, then the bytes; or, flagged as a
            // stream, the stream's id and its size.
            let stream = le16(&v, 0) & 1 != 0;
            let held = || {
                let len = usize::from(le16(&v, 2));
                crate::bytes::at(&v, 4, len).map(<[u8]>::to_vec)
            };
            if name == decmpfs::ATTR.as_bytes() {
                out.decmpfs = match stream {
                    true => self.stream(fs, le64(&v, 4), le64(&v, 12), ATTR_MAX).ok(),
                    false => held(),
                };
            } else if name == decmpfs::RESOURCE_FORK_ATTR.as_bytes() && stream {
                out.fork = Some((le64(&v, 4), le64(&v, 12)));
            }
        }
        Ok(out)
    }

    /// The `size` bytes of the data stream `id`, if they are at most `bound`.
    fn stream(&self, fs: &mut Fs, id: u64, size: u64, bound: u64) -> Res<Vec<u8>> {
        if size > bound {
            return Err(Bad);
        }
        let mut out = Vec::new();
        let mut extents = self.extents(fs, id)?;
        match read_extents(fs, &mut extents, size, &mut out) {
            true => Ok(out),
            false => Err(Bad),
        }
    }

    /// The bytes of file `id`: held when they are at most `cap`, else read as
    /// they go. A compressed file is unpacked, and is not read as it goes.
    fn file<'x>(&self, fs: &'x mut Fs<'_, '_>, id: u64, cap: u64) -> Got<'x> {
        let Ok(inode) = self.inode(fs, id) else {
            return Got::Why("APFS file whose inode could not be read");
        };
        if inode.flags & decmpfs::COMPRESSED_FLAG != 0 {
            let attrs = self.attrs(fs, id).unwrap_or_default();
            if let Some(attr) = attrs.decmpfs {
                let fork = decmpfs::header(&attr)
                    .filter(|h| decmpfs::in_fork(h.kind))
                    .and(attrs.fork)
                    // A fork holds the bytes in blocks, a little over their number.
                    .and_then(|(stream, size)| {
                        let bound = cap.saturating_add(cap / 32).saturating_add(4096);
                        self.stream(fs, stream, size, bound).ok()
                    });
                return decmpfs::unpack(&attr, fork.as_deref(), cap);
            }
            if inode.size == 0 {
                return Got::Why("compressed file (decmpfs) without its attribute");
            }
        }
        let Ok(mut extents) = self.extents(fs, inode.stream) else {
            return Got::Why("APFS file whose extents could not be read");
        };
        extents.sort_by_key(|e| e.at);
        let plan = Spans {
            extents: extents.into_iter(),
            pending: None,
            block: fs.block,
            size: inode.size,
            at: 0,
        };
        read_file(&mut *fs.v, Pieces::new(plan, inode.size), inode.size, cap)
    }
}

/// The stretches of a file, from its extents in order of their place in it: a
/// hole between them or after the last reads as zeros.
struct Spans {
    extents: std::vec::IntoIter<Extent>,
    /// An extent held back while the hole before it is given.
    pending: Option<Extent>,
    block: u64,
    size: u64,
    /// How many bytes of the file the stretches given so far cover.
    at: u64,
}

impl Plan for Spans {
    fn next(&mut self, _: &mut Vol) -> Next {
        loop {
            if self.at >= self.size {
                return Next::End;
            }
            let Some(e) = self.pending.take().or_else(|| self.extents.next()) else {
                let rest = self.size.saturating_sub(self.at);
                self.at = self.size;
                return Next::Piece(Piece::Zeros(rest));
            };
            if e.at > self.at {
                let gap =
                    e.at.saturating_sub(self.at)
                        .min(self.size.saturating_sub(self.at));
                self.at = self.at.saturating_add(gap);
                self.pending = Some(e);
                return Next::Piece(Piece::Zeros(gap));
            }
            // An extent that overlaps what was given gives only the rest.
            let skip = self.at.saturating_sub(e.at);
            if skip >= e.len {
                continue;
            }
            let take = e
                .len
                .saturating_sub(skip)
                .min(self.size.saturating_sub(self.at));
            self.at = self.at.saturating_add(take);
            return match e.block {
                0 => Next::Piece(Piece::Zeros(take)),
                block => match block
                    .checked_mul(self.block)
                    .and_then(|b| b.checked_add(skip))
                {
                    Some(at) => Next::Piece(Piece::Disk(at, take)),
                    None => Next::Broken,
                },
            };
        }
    }
}

/// Append the first `size` bytes of a file to `out`: the extents in order of
/// their place in the file, a hole between them or after the last reading as
/// zeros. False when a block cannot be read; what was read stays.
fn read_extents(fs: &mut Fs, extents: &mut [Extent], size: u64, out: &mut Vec<u8>) -> bool {
    extents.sort_by_key(|e| e.at);
    let zeros = |out: &mut Vec<u8>, n: u64| {
        out.resize(out.len().saturating_add(crate::bytes::to_usize(n)), 0);
    };
    let mut pos = 0u64;
    for e in extents.iter() {
        if pos >= size {
            break;
        }
        if e.at > pos {
            let gap = e.at.saturating_sub(pos).min(size.saturating_sub(pos));
            zeros(out, gap);
            pos = pos.saturating_add(gap);
            if pos >= size {
                break;
            }
        }
        // An extent that overlaps what was read gives only the rest.
        let skip = pos.saturating_sub(e.at);
        if skip >= e.len {
            continue;
        }
        let take = e.len.saturating_sub(skip).min(size.saturating_sub(pos));
        match e.block {
            0 => zeros(out, take),
            block => {
                let Some(at) = block
                    .checked_mul(fs.block)
                    .and_then(|b| b.checked_add(skip))
                else {
                    return false;
                };
                if !fs.v.append(at, crate::bytes::to_usize(take), out) {
                    return false;
                }
            }
        }
        pos = pos.saturating_add(take);
    }
    zeros(out, size.saturating_sub(pos));
    true
}

/// The folders and files the directory records of a volume name.
#[derive(Default)]
struct Names {
    folders: HashMap<u64, (u64, String)>,
    files: Vec<Named>,
}

impl Names {
    /// The path of `name` in folder `parent`, from the root. A folder whose
    /// chain does not reach the root (a record missing, or a loop) stands
    /// where the chain broke, by its id.
    fn path(&self, parent: u64, name: &str) -> String {
        let mut parts = vec![name];
        let mut at = parent;
        for _ in 0..MAX_PATH_DEPTH {
            if at == ROOT {
                break;
            }
            let Some((up, folder)) = self.folders.get(&at) else {
                break;
            };
            parts.push(folder);
            at = *up;
        }
        let lost = (at != ROOT).then(|| format!("<apfs-folder-{at}>"));
        parts.extend(lost.as_deref());
        parts.reverse();
        format!("/{}", parts.join("/"))
    }
}

/// The container: its newest superblock and its object map.
struct Container {
    sb: Vec<u8>,
    omap: Omap,
}

fn open(fs: &mut Fs) -> Option<Container> {
    // The block size is in the first block, whose size it gives.
    fs.block = 4096;
    let first = fs.raw(0)?;
    let size = le32(&first, 36);
    if le32(&first, 32) != NX_MAGIC || !(4096..=65536).contains(&size) || !size.is_power_of_two() {
        return None;
    }
    fs.block = u64::from(size);
    let mut sb = fs.raw(0)?;
    // The newest superblock of the checkpoint area, if it has one the first
    // block does not: that block is only the one written at format time. One
    // whose checksum holds is preferred to a newer one whose does not, a write
    // that was cut short, as the system that mounts the container does.
    let rank = |b: &[u8]| (sum_holds(b), le64(b, 16));
    let (base, blocks) = (le64(&sb, 112), u64::from(le32(&sb, 104)));
    if base >> 63 == 0 {
        for n in 0..blocks.min(MAX_CHECKPOINT_BLOCKS) {
            let Some(b) = base.checked_add(n).and_then(|n| fs.raw(n)) else {
                continue;
            };
            let is_sb = le32(&b, 24) & 0xFFFF == 1 && le32(&b, 32) == NX_MAGIC;
            if is_sb && le32(&b, 36) == size && rank(&b) > rank(&sb) {
                sb = b;
            }
        }
    }
    if fs.strict && !sum_holds(&sb) {
        return None;
    }
    // Nothing is read from past the container the superblock describes.
    fs.v.len = fs.v.len.min(le64(&sb, 40).saturating_mul(fs.block));
    let omap = load_omap(fs, le64(&sb, 160), le64(&sb, 16))?;
    Some(Container { sb, omap })
}

/// Whether `head`, the start of a volume, holds the superblock of an APFS
/// container: its magic, and a block size that is a power of two from 4 KiB to
/// 64 KiB.
pub(crate) fn is_apfs(head: &[u8]) -> bool {
    le32(head, 32) == NX_MAGIC
        && (4096..=65536).contains(&le32(head, 36))
        && le32(head, 36).is_power_of_two()
}

/// Walk the APFS container `disk`, which starts at its first block, handing
/// each file to `visit`.
pub(crate) fn walk_volume<D: Read + Seek, R>(
    mut disk: D,
    budget: &mut Budget,
    visit: Emit<R>,
) -> Result<Option<R>, LimitHit> {
    let len = disk
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("APFS container: {e}")))?;
    let max = crate::bytes::to_usize(budget.limits().max_buffer_bytes);
    let mut v = Vol {
        disk: &mut disk,
        len,
        max,
    };
    let mut fs = Fs {
        v: &mut v,
        block: 4096,
        cache: HashMap::new(),
        strict: budget.should_verify_checksums(),
    };
    let Some(container) = open(&mut fs) else {
        return Err(LimitHit::corrupt(
            "apfs open: the container superblock or its object map is unreadable".into(),
        ));
    };

    // The volumes, each by the block its id maps to.
    let listed = (0..le32(&container.sb, 180).min(100) as usize)
        .map(|i| le64(&container.sb, 184usize.saturating_add(i.saturating_mul(8))))
        .filter(|&id| id != 0)
        .collect::<Vec<_>>();
    let multiple = listed.len() > 1;
    for (n, id) in listed.into_iter().enumerate() {
        let sb = container
            .omap
            .get(&id)
            .copied()
            .flatten()
            .and_then(|block| fs.block(block))
            .filter(|sb| le32(sb, 32) == APSB_MAGIC);
        let Some(sb) = sb else {
            budget.count_entry()?;
            let note = Entry::unsupported(
                format!("<apfs-volume-{n}>"),
                0,
                false,
                "APFS volume that could not be read",
            );
            if let Some(r) = visit(Found::Held(note), budget) {
                return Ok(Some(r));
            }
            continue;
        };
        if let Some(r) = walk_one(&mut fs, &sb, multiple, n, budget, &mut *visit)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Walk the volume whose superblock is `sb`.
fn walk_one<R>(
    fs: &mut Fs,
    sb: &[u8],
    multiple: bool,
    n: usize,
    budget: &mut Budget,
    visit: Emit<R>,
) -> Result<Option<R>, LimitHit> {
    // The name is 256 bytes, ended by a NUL, 704 bytes in.
    let name = sb.get(704..960).unwrap_or_default();
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    let name = String::from_utf8_lossy(name).into_owned();
    let name = if name.is_empty() {
        format!("volume-{n}")
    } else {
        name
    };
    if le64(sb, 264) & FS_UNENCRYPTED == 0 {
        budget.count_entry()?;
        let note = Entry::unsupported(
            format!("<apfs-volume:{name}>"),
            0,
            true,
            "encrypted APFS volume; its files were not read",
        );
        return Ok(visit(Found::Held(note), budget));
    }
    let prefix = if multiple {
        format!("/{name}")
    } else {
        String::new()
    };
    let unreadable = |budget: &mut Budget, visit: Emit<R>| {
        budget.count_entry()?;
        let note = Entry::unsupported(
            format!("<apfs-volume:{name}>"),
            0,
            false,
            "APFS volume whose file-system tree could not be read",
        );
        Ok::<_, LimitHit>(visit(Found::Held(note), budget))
    };

    // The volume's object map, as of its own transaction, gives the tree.
    let Some(omap) = load_omap(fs, le64(sb, 128), le64(sb, 16)) else {
        return unreadable(budget, visit);
    };
    let Some(root) = omap.get(&le64(sb, 136)).copied().flatten() else {
        return unreadable(budget, visit);
    };
    let volume = Volume {
        tree: Tree {
            root,
            fixed: None,
            omap: Some(&omap),
        },
    };

    // The directory records: every folder and file, up to the member limit.
    let limit = crate::bytes::to_usize(budget.limits().max_members);
    let mut names = Names::default();
    let mut capped = false;
    let mut intact = true;
    match volume.records(fs, 0, 0) {
        Err(Bad) => intact = false,
        Ok(mut c) => loop {
            match c.next(fs, &volume.tree) {
                Err(Bad) => {
                    intact = false;
                    break;
                }
                Ok(None) => break,
                Ok(Some((k, v))) => {
                    let (parent, ty) = key_of(&k);
                    if ty != J_DREC {
                        continue;
                    }
                    if names.files.len().saturating_add(names.folders.len()) >= limit {
                        capped = true;
                        break;
                    }
                    let Some(name) = drec_name(&k) else { continue };
                    let (id, kind) = (le64(&v, 0), le16(&v, 16) & 0xF);
                    match kind {
                        DT_DIR => {
                            names.folders.insert(id, (parent, name));
                        }
                        DT_LNK => {}
                        _ => names.files.push(Named { id, parent, name }),
                    }
                }
            }
        },
    }

    for f in &names.files {
        let path = format!("{prefix}{}", names.path(f.parent, &f.name));
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let got = volume.file(fs, f.id, cap);
        if let Some(r) = hand(budget, &mut *visit, path, VolAttrs::default(), got) {
            return Ok(Some(r));
        }
    }
    if capped {
        return Err(LimitHit::of_kind(
            crate::LimitKind::MaxFiles,
            format!("file count > {limit}"),
        ));
    }
    if !intact {
        return Err(LimitHit::corrupt(
            "apfs walk: file-system tree damaged; the files before the damage were scanned".into(),
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
    use std::io::{Cursor, Write};

    const BS: usize = 4096;

    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// The block with its checksum.
    fn seal(mut b: Vec<u8>) -> Vec<u8> {
        let sum = fletcher64(&b[8..]);
        b[..8].copy_from_slice(&sum.to_le_bytes());
        b
    }

    /// A node of a B-tree. Keys and values are in the order given; a tree with
    /// `fixed` sizes has only keys and values of those.
    fn bnode(
        flags: u16,
        level: u16,
        fixed: Option<(usize, usize)>,
        recs: &[(Vec<u8>, Vec<u8>)],
    ) -> Vec<u8> {
        let mut b = vec![0u8; BS];
        let fixed_flag = if fixed.is_some() { FIXED_NODE } else { 0 };
        put16(&mut b, 32, flags | fixed_flag);
        put16(&mut b, 34, level);
        put32(&mut b, 36, recs.len() as u32);
        let entry = if fixed.is_some() { 4 } else { 8 };
        put16(&mut b, 42, (recs.len() * entry) as u16);
        let keys = 56 + recs.len() * entry;
        let vals = if flags & ROOT_NODE != 0 { BS - 40 } else { BS };
        let (mut k_at, mut v_back) = (0, 0);
        for (i, (k, v)) in recs.iter().enumerate() {
            b[keys + k_at..keys + k_at + k.len()].copy_from_slice(k);
            v_back += v.len();
            b[vals - v_back..vals - v_back + v.len()].copy_from_slice(v);
            let e = 56 + i * entry;
            put16(&mut b, e, k_at as u16);
            if fixed.is_some() {
                put16(&mut b, e + 2, v_back as u16);
            } else {
                put16(&mut b, e + 2, k.len() as u16);
                put16(&mut b, e + 4, v_back as u16);
                put16(&mut b, e + 6, v.len() as u16);
            }
            k_at += k.len();
        }
        seal(b)
    }

    /// An object-map record: the block `oid` is at, from transaction `xid`.
    fn mapping(oid: u64, xid: u64, block: u64, flags: u32) -> (Vec<u8>, Vec<u8>) {
        let mut k = oid.to_le_bytes().to_vec();
        k.extend_from_slice(&xid.to_le_bytes());
        let mut v = flags.to_le_bytes().to_vec();
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&block.to_le_bytes());
        (k, v)
    }

    /// The blocks of a container being laid out; block 0 is left for its
    /// superblock.
    struct Cont {
        blocks: Vec<Vec<u8>>,
    }

    impl Cont {
        fn new() -> Cont {
            Cont {
                blocks: vec![vec![0; BS]],
            }
        }

        fn push(&mut self, b: Vec<u8>) -> u64 {
            self.blocks.push(b);
            self.blocks.len() as u64 - 1
        }

        /// File bytes in blocks of their own: the first block.
        fn data(&mut self, bytes: &[u8]) -> u64 {
            let first = self.blocks.len() as u64;
            for c in bytes.chunks(BS) {
                let mut b = c.to_vec();
                b.resize(BS, 0);
                self.blocks.push(b);
            }
            first
        }

        /// An object map holding `recs`: the block of its object.
        fn omap(&mut self, recs: &[(Vec<u8>, Vec<u8>)]) -> u64 {
            let root = self.push(bnode(ROOT_NODE | LEAF_NODE, 0, Some((16, 16)), recs));
            let mut o = vec![0u8; BS];
            put64(&mut o, 48, root);
            self.push(seal(o))
        }

        /// The file-system tree of `recs` (in key order) in two leaves under
        /// a root: the root's id, and the object map that gives its nodes.
        fn fs_tree(&mut self, recs: &[(Vec<u8>, Vec<u8>)], xid: u64) -> (u64, u64) {
            let (a, b) = recs.split_at(recs.len() / 2);
            let leaf_a = self.push(bnode(LEAF_NODE, 0, None, a));
            let leaf_b = self.push(bnode(LEAF_NODE, 0, None, b));
            let index = [
                (a[0].0.clone(), 1030u64.to_le_bytes().to_vec()),
                (b[0].0.clone(), 1031u64.to_le_bytes().to_vec()),
            ];
            let root = self.push(bnode(ROOT_NODE, 1, None, &index));
            let omap = self.omap(&[
                // An older mapping of the first leaf, to a block that is no tree.
                mapping(1030, xid - 1, 0, 0),
                mapping(1030, xid, leaf_a, 0),
                mapping(1031, xid, leaf_b, 0),
                mapping(1032, xid, root, 0),
            ]);
            (1032, omap)
        }

        /// A volume over `recs`: the block of its superblock.
        fn volume(&mut self, name: &str, flags: u64, recs: &[(Vec<u8>, Vec<u8>)]) -> u64 {
            let (root_oid, omap) = self.fs_tree(recs, 10);
            let mut sb = vec![0u8; BS];
            put64(&mut sb, 16, 10);
            put32(&mut sb, 24, 13);
            put32(&mut sb, 32, APSB_MAGIC);
            put64(&mut sb, 128, omap);
            put64(&mut sb, 136, root_oid);
            put64(&mut sb, 264, flags);
            sb[704..704 + name.len()].copy_from_slice(name.as_bytes());
            self.push(seal(sb))
        }

        /// The container: its blocks, and a superblock over the volumes
        /// (each by the block of its superblock).
        fn finish(mut self, volumes: &[u64]) -> Vec<u8> {
            let ids: Vec<u64> = (0..volumes.len() as u64).map(|i| 1100 + i).collect();
            let omap = self.omap(
                &ids.iter()
                    .zip(volumes)
                    .map(|(&id, &b)| mapping(id, 10, b, 0))
                    .collect::<Vec<_>>(),
            );
            self.blocks[0] = self.superblock(10, omap, &ids, 0, 0);
            self.blocks.concat()
        }

        fn superblock(&self, xid: u64, omap: u64, ids: &[u64], desc: u64, descs: u32) -> Vec<u8> {
            let mut sb = vec![0u8; BS];
            put64(&mut sb, 16, xid);
            put32(&mut sb, 24, 1);
            put32(&mut sb, 32, NX_MAGIC);
            put32(&mut sb, 36, BS as u32);
            put64(&mut sb, 40, self.blocks.len() as u64 + 8);
            put32(&mut sb, 104, descs);
            put64(&mut sb, 112, desc);
            put64(&mut sb, 160, omap);
            put32(&mut sb, 180, 100);
            for (i, id) in ids.iter().enumerate() {
                put64(&mut sb, 184 + 8 * i, *id);
            }
            seal(sb)
        }
    }

    /// The key of a record of type `ty` of object `id`, then `tail`.
    fn key(id: u64, ty: u8, tail: &[u8]) -> Vec<u8> {
        let mut k = (id | (u64::from(ty) << 60)).to_le_bytes().to_vec();
        k.extend_from_slice(tail);
        k
    }

    /// An inode: its parent, the id its extents are keyed by, its mode, its
    /// flags and its size (in a data stream field).
    fn inode(id: u64, parent: u64, stream: u64, flags: u32, size: u64) -> (Vec<u8>, Vec<u8>) {
        let mut v = vec![0u8; 92];
        put64(&mut v, 0, parent);
        put64(&mut v, 8, stream);
        put32(&mut v, 68, flags);
        put16(&mut v, 80, 0o100644);
        v.extend_from_slice(&[1, 0, 48, 0, 8, 0, 40, 0]);
        let mut d = size.to_le_bytes().to_vec();
        d.resize(40, 0);
        v.extend(d);
        (key(id, J_INODE, &[]), v)
    }

    /// A directory record: `parent` holds `name`, the object `id` of kind `dt`.
    fn drec(parent: u64, name: &str, id: u64, dt: u16) -> (Vec<u8>, Vec<u8>) {
        let mut tail = (name.len() as u32 + 1).to_le_bytes().to_vec();
        tail.extend_from_slice(name.as_bytes());
        tail.push(0);
        let mut v = id.to_le_bytes().to_vec();
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&dt.to_le_bytes());
        (key(parent, J_DREC, &tail), v)
    }

    /// An extent of the stream `id`: `len` bytes at `at` in the file, in
    /// blocks from `block` (0: a hole).
    fn extent(id: u64, at: u64, len: u64, block: u64) -> (Vec<u8>, Vec<u8>) {
        let mut v = len.to_le_bytes().to_vec();
        v.extend_from_slice(&block.to_le_bytes());
        v.extend_from_slice(&[0; 8]);
        (key(id, J_FILE_EXTENT, &at.to_le_bytes()), v)
    }

    /// An attribute of object `id`, held in its record, or as a stream.
    fn xattr(id: u64, name: &str, value: &[u8], stream: Option<(u64, u64)>) -> (Vec<u8>, Vec<u8>) {
        let mut tail = (name.len() as u16 + 1).to_le_bytes().to_vec();
        tail.extend_from_slice(name.as_bytes());
        tail.push(0);
        let mut v = Vec::new();
        match stream {
            None => {
                v.extend_from_slice(&2u16.to_le_bytes());
                v.extend_from_slice(&(value.len() as u16).to_le_bytes());
                v.extend_from_slice(value);
            }
            Some((obj, size)) => {
                v.extend_from_slice(&1u16.to_le_bytes());
                v.extend_from_slice(&48u16.to_le_bytes());
                v.extend_from_slice(&obj.to_le_bytes());
                v.extend_from_slice(&size.to_le_bytes());
                v.resize(52, 0);
            }
        }
        (key(id, J_XATTR, &tail), v)
    }

    /// Records in the order of the tree: by object, then type; those of one
    /// object and type stay as given.
    fn sorted(mut recs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
        recs.sort_by_key(|(k, _)| key_of(k));
        recs
    }

    fn run(img: &[u8], limits: Limits) -> (Vec<Entry>, Result<(), LimitHit>) {
        let mut budget = Budget::new(limits);
        let mut out = Vec::new();
        let end = walk_volume(Cursor::new(img.to_vec()), &mut budget, &mut |e, _| {
            out.push(e.whole());
            None::<()>
        });
        (out, end.map(|_| ()))
    }

    fn named(entries: &[Entry]) -> Vec<(&str, &[u8])> {
        entries.iter().map(|e| (&e.name[..], &e.data[..])).collect()
    }

    const DT_REG: u16 = 8;
    const PACKED: u32 = 0x20;

    /// Folders and files, with a file in a hole-ridden stream and a clone.
    fn tree_of_folders() -> Vec<u8> {
        let mut c = Cont::new();
        let (a, b, d) = (c.data(b"in root"), c.data(&[b'B'; BS]), c.data(&[b'D'; BS]));
        let sub = c.data(b"in sub");
        let recs = sorted(vec![
            drec(2, "a.txt", 20, DT_REG),
            drec(2, "dir", 16, DT_DIR),
            drec(2, "link", 23, DT_LNK),
            drec(16, "b.txt", 21, DT_REG),
            drec(16, "sub", 17, DT_DIR),
            // A clone: its inode names another stream.
            drec(17, "c.txt", 22, DT_REG),
            inode(20, 2, 20, 0, 7),
            extent(20, 0, BS as u64, a),
            // Two blocks with a hole between, and a hole at the end.
            inode(21, 16, 21, 0, 4 * BS as u64),
            extent(21, 0, BS as u64, b),
            extent(21, 2 * BS as u64, BS as u64, d),
            inode(22, 17, 77, 0, 6),
            extent(77, 0, BS as u64, sub),
        ]);
        let v = c.volume("Data", FS_UNENCRYPTED, &recs);
        c.finish(&[v])
    }

    #[test]
    fn the_files_of_a_tree_of_folders_come_out_under_their_paths() {
        let (entries, end) = run(&tree_of_folders(), Limits::default());
        assert!(end.is_ok());
        let mut hole = vec![b'B'; BS];
        hole.extend_from_slice(&[0; BS]);
        hole.extend_from_slice(&[b'D'; BS]);
        hole.extend_from_slice(&[0; BS]);
        assert_eq!(
            named(&entries),
            [
                ("/a.txt", &b"in root"[..]),
                ("/dir/b.txt", &hole[..]),
                ("/dir/sub/c.txt", b"in sub"),
            ]
        );
    }

    #[test]
    fn compressed_files_are_unpacked_from_an_attribute_or_a_stream_fork() {
        let text = b"compressed text, compressed text, compressed text".to_vec();
        let z = |data: &[u8]| {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        };
        let attr = |kind: u32, payload: &[u8]| {
            let mut a = b"fpmc".to_vec();
            a.extend_from_slice(&kind.to_le_bytes());
            a.extend_from_slice(&(text.len() as u64).to_le_bytes());
            a.extend_from_slice(payload);
            a
        };
        // Type 4: one zlib block, the table 4 bytes into the fork.
        let block = z(&text);
        let mut fork = vec![0, 0, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0];
        fork.extend_from_slice(&(block.len() as u32).to_le_bytes());
        fork.extend_from_slice(&block);

        let mut c = Cont::new();
        let fork_at = c.data(&fork);
        let plain = c.data(b"plain");
        let recs = sorted(vec![
            drec(2, "inline", 30, DT_REG),
            drec(2, "forked", 31, DT_REG),
            drec(2, "plain", 32, DT_REG),
            inode(30, 2, 30, PACKED, 0),
            xattr(30, "com.apple.FinderInfo", b"zz", None),
            xattr(30, "com.apple.decmpfs", &attr(3, &z(&text)), None),
            inode(31, 2, 31, PACKED, 0),
            xattr(31, "com.apple.decmpfs", &attr(4, &[]), None),
            xattr(
                31,
                "com.apple.ResourceFork",
                &[],
                Some((900, fork.len() as u64)),
            ),
            extent(900, 0, BS as u64, fork_at),
            // Not marked: its attribute is not looked for.
            inode(32, 2, 32, 0, 5),
            xattr(32, "com.apple.decmpfs", &attr(3, &z(b"wrong")), None),
            extent(32, 0, BS as u64, plain),
        ]);
        let v = c.volume("V", FS_UNENCRYPTED, &recs);
        let (entries, end) = run(&c.finish(&[v]), Limits::default());
        assert!(end.is_ok());
        assert_eq!(
            named(&entries),
            [
                ("/inline", &text[..]),
                ("/forked", &text[..]),
                ("/plain", b"plain")
            ]
        );
        assert!(entries.iter().all(|e| e.unsupported.is_none()));
    }

    #[test]
    fn every_volume_is_walked_and_an_encrypted_one_is_reported() {
        let mut c = Cont::new();
        let one = c.data(b"one");
        let two = c.data(b"two");
        let first = sorted(vec![
            drec(2, "f", 20, DT_REG),
            inode(20, 2, 20, 0, 3),
            extent(20, 0, BS as u64, one),
        ]);
        let second = sorted(vec![
            drec(2, "f", 20, DT_REG),
            inode(20, 2, 20, 0, 3),
            extent(20, 0, BS as u64, two),
        ]);
        let (a, b) = (c.volume("First", 1, &first), c.volume("Second", 1, &second));
        let locked = c.volume("Locked", 0, &first);
        let (entries, end) = run(&c.finish(&[a, b, locked]), Limits::default());
        assert!(end.is_ok());
        assert_eq!(
            named(&entries[..2]),
            [("/First/f", &b"one"[..]), ("/Second/f", b"two")]
        );
        assert_eq!(entries[2].name, "<apfs-volume:Locked>");
        assert!(entries[2].encrypted && entries[2].unsupported.is_some());
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn what_the_volume_cannot_give_of_a_file_is_reported() {
        let mut c = Cont::new();
        let recs = sorted(vec![
            drec(2, "no-inode", 20, DT_REG),
            drec(2, "no-blocks", 21, DT_REG),
            inode(21, 2, 21, 0, 100),
            // Past the end of the container.
            drec(2, "outside", 22, DT_REG),
            inode(22, 2, 22, 0, 100),
            extent(22, 0, 100, 5000),
        ]);
        let v = c.volume("V", 1, &recs);
        let (entries, end) = run(&c.finish(&[v]), Limits::default());
        assert!(end.is_ok());
        let got: Vec<_> = entries
            .iter()
            .map(|e| (&e.name[..], e.unsupported.is_some(), e.data.len()))
            .collect();
        // A file with no extents is a hole as long as its size says.
        assert_eq!(
            got,
            [
                ("/no-inode", true, 0),
                ("/no-blocks", false, 100),
                ("/outside", true, 0)
            ]
        );
        assert!(entries[0].unsupported.unwrap().contains("inode"));
        assert_eq!(
            entries[2].unsupported,
            Some("file could not be read from the volume")
        );
    }

    #[test]
    fn the_newest_superblock_of_the_checkpoint_area_is_the_one() {
        let mut c = Cont::new();
        let old = c.data(b"old");
        let new = c.data(b"new");
        let make = |c: &mut Cont, block: u64| {
            let recs = sorted(vec![
                drec(2, "f", 20, DT_REG),
                inode(20, 2, 20, 0, 3),
                extent(20, 0, BS as u64, block),
            ]);
            c.volume("V", 1, &recs)
        };
        let (v_old, v_new) = (make(&mut c, old), make(&mut c, new));
        // The container's first block names the old volume; the area, two
        // blocks later, holds a superblock of a later transaction naming the new.
        let omap = c.omap(&[mapping(1100, 10, v_old, 0), mapping(1101, 11, v_new, 0)]);
        let area = c.blocks.len() as u64;
        let newer = c.superblock(11, omap, &[1101], 0, 0);
        c.blocks.push(vec![0; BS]);
        c.blocks.push(newer);
        c.blocks[0] = c.superblock(10, omap, &[1100], area, 2);
        let (entries, end) = run(&c.blocks.concat(), Limits::default());
        assert!(end.is_ok());
        assert_eq!(named(&entries), [("/f", &b"new"[..])]);
    }

    /// A superblock newer than the others whose checksum does not hold is a
    /// write that was cut short: the one before it is the container's. With none
    /// that holds, the newest is.
    #[test]
    fn a_newer_superblock_that_was_cut_short_is_passed_over() {
        let mut c = Cont::new();
        let (old, new) = (c.data(b"old"), c.data(b"new"));
        let make = |c: &mut Cont, block: u64| {
            let recs = sorted(vec![
                drec(2, "f", 20, DT_REG),
                inode(20, 2, 20, 0, 3),
                extent(20, 0, BS as u64, block),
            ]);
            c.volume("V", 1, &recs)
        };
        let (v_old, v_new) = (make(&mut c, old), make(&mut c, new));
        let omap = c.omap(&[mapping(1100, 10, v_old, 0), mapping(1101, 11, v_new, 0)]);
        let area = c.blocks.len() as u64;
        let newer = c.superblock(11, omap, &[1101], 0, 0);
        c.blocks.push(vec![0; BS]);
        c.blocks.push(newer);
        c.blocks[0] = c.superblock(10, omap, &[1100], area, 2);
        let mut img = c.blocks.concat();
        let at = usize::try_from(area).unwrap() + 1;
        img[at * BS] ^= 0xff;
        let (entries, _) = run(&img, Limits::default());
        assert_eq!(named(&entries), [("/f", &b"old"[..])]);
        // The first block's does not hold either: the newest is the best there is.
        img[0] ^= 0xff;
        let (entries, _) = run(&img, Limits::default());
        assert_eq!(named(&entries), [("/f", &b"new"[..])]);
    }

    #[test]
    fn files_past_the_buffer_limit_are_read_as_they_go() {
        let img = tree_of_folders();
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 3,
            ..Limits::default()
        });
        let (e, end) = collected(|emit| walk_volume(Cursor::new(img.to_vec()), &mut budget, emit));
        end.unwrap();
        // The same bytes as held, holes included, and none of them held.
        let (held, end) = run(&img, Limits::default());
        assert!(end.is_ok());
        assert_eq!(e.len(), held.len());
        assert!(e.iter().any(|(m, _)| m.data.contains(&0)), "a hole");
        for ((m, streamed), h) in e.iter().zip(&held) {
            assert_eq!((&m.name, &m.data), (&h.name, &h.data));
            assert_eq!(*streamed, m.data.len() > 3, "{}", m.name);
        }
    }

    #[test]
    fn a_tree_larger_than_the_member_limit_is_walked_to_it_and_then_stops() {
        let limits = Limits {
            max_members: 2,
            ..Limits::default()
        };
        let (entries, end) = run(&tree_of_folders(), limits);
        // The directory records are "a.txt" and "dir", which are kept, and
        // "link", which is over.
        assert_eq!(named(&entries), [("/a.txt", &b"in root"[..])]);
        assert_eq!(end.expect_err("the limit").kind, crate::LimitKind::MaxFiles);
    }

    /// The block of the root of the tree of `img`'s last volume; its leaves
    /// are the two before it.
    fn root_of(img: &[u8]) -> usize {
        img.chunks(BS)
            .rposition(|b| le16(b, 32) == ROOT_NODE && le16(b, 34) == 1)
            .unwrap()
    }

    #[test]
    fn a_damaged_leaf_ends_the_walk_after_the_files_before_it() {
        // Ten directory records and two inodes, which two leaves split in
        // half: the second leaf has the last four of the names.
        let mut recs: Vec<_> = (0..10)
            .map(|i| drec(2, &format!("f{i}"), 20 + i, DT_REG))
            .collect();
        recs.push(inode(40, 2, 40, 0, 0));
        recs.push(inode(41, 2, 41, 0, 0));
        let mut c = Cont::new();
        let v = c.volume("V", 1, &sorted(recs));
        let mut img = c.finish(&[v]);
        let root = root_of(&img);

        // A node that says it has more keys than it has room for, its checksum
        // made good again.
        let spoil = |img: &mut Vec<u8>, block: usize| {
            let b = &mut img[block * BS..(block + 1) * BS];
            put32(b, 36, u32::MAX);
            let sum = fletcher64(&b[8..]);
            b[..8].copy_from_slice(&sum.to_le_bytes());
        };

        // The second leaf spoiled: the names of the first are walked, and
        // their inodes, which are in the second, are not found.
        let mut bad = img.clone();
        spoil(&mut bad, root - 1);
        let (entries, end) = run(&bad, Limits::default());
        assert!(end.expect_err("damage").is_corrupt());
        assert_eq!(entries.len(), 6);
        assert!(entries.iter().all(|e| e.unsupported.is_some()));

        // The first spoiled: the tree cannot be entered.
        spoil(&mut img, root - 2);
        let (entries, end) = run(&img, Limits::default());
        assert!(end.expect_err("damage").is_corrupt());
        assert!(entries.is_empty());
    }

    /// Ten files and the leaves that hold them, and the block of the root of
    /// their tree.
    fn ten_files() -> (Vec<u8>, usize) {
        let mut recs: Vec<_> = (0..10)
            .map(|i| drec(2, &format!("f{i}"), 20 + i, DT_REG))
            .collect();
        recs.push(inode(40, 2, 40, 0, 0));
        recs.push(inode(41, 2, 41, 0, 0));
        let mut c = Cont::new();
        let v = c.volume("V", 1, &sorted(recs));
        let img = c.finish(&[v]);
        let root = root_of(&img);
        (img, root)
    }

    /// A checksum that does not hold keeps nothing from being scanned: the
    /// block is read as it is.
    #[test]
    fn a_checksum_that_does_not_hold_is_not_a_reason_not_to_read() {
        let (mut img, root) = ten_files();
        let (clean, _) = run(&img, Limits::default());
        for block in [root, root - 1, root - 2, 0] {
            img[block * BS] ^= 0xff;
        }
        let (entries, end) = run(&img, Limits::default());
        assert!(end.is_ok());
        assert_eq!(named(&entries), named(&clean));
        assert_eq!(entries.len(), 10);
    }

    /// With checksums checked, the same blocks are refused.
    #[cfg(feature = "checksums")]
    #[test]
    fn a_checksum_that_does_not_hold_is_refused_when_checksums_are_checked() {
        let strict = |img: &[u8]| {
            let mut budget = Budget::new(Limits::default());
            budget.set_verify_checksums(true);
            let mut out = Vec::new();
            let end = walk_volume(Cursor::new(img.to_vec()), &mut budget, &mut |e, _| {
                out.push(e.whole());
                None::<()>
            });
            (out, end)
        };
        let (mut img, root) = ten_files();
        assert_eq!(strict(&img).0.len(), 10);
        let mut bad = img.clone();
        bad[(root - 1) * BS + 100] ^= 0xff;
        let (entries, end) = strict(&bad);
        assert!(end.expect_err("damage").is_corrupt());
        assert_eq!(entries.len(), 6);
        img[0] ^= 0xff;
        assert!(strict(&img).1.is_err());
    }

    #[test]
    fn nothing_is_a_container_but_a_checked_superblock_with_an_object_map() {
        let good = tree_of_folders();
        // The magic, the block size, the object map's block: each in turn,
        // the checksum made good again, so that only it is wrong.
        for (at, byte) in [(32, b'X'), (37, 0x20), (161, 0xff)] {
            let mut bad = good.clone();
            bad[at] ^= byte;
            let sum = fletcher64(&bad[8..BS]);
            bad[..8].copy_from_slice(&sum.to_le_bytes());
            let (entries, end) = run(&bad, Limits::default());
            assert!(entries.is_empty(), "byte {at}");
            assert!(end.expect_err("not a container").is_corrupt(), "byte {at}");
        }
        assert!(run(&good[..BS - 1], Limits::default()).1.is_err());
    }

    /// Whatever a container says, the walk ends: every byte of the trees
    /// changed, in turn, to each of a few values, the checksums made good.
    #[test]
    fn damaged_containers_end_the_walk_without_a_panic() {
        let good = tree_of_folders();
        for at in (0..good.len()).step_by(7) {
            for byte in [0x00, 0x01, 0x7f, 0xff] {
                let mut bad = good.clone();
                bad[at] = byte;
                let block = at / BS * BS;
                let sum = fletcher64(&bad[block + 8..block + BS]);
                bad[block..block + 8].copy_from_slice(&sum.to_le_bytes());
                let _ = run(&bad, Limits::default());
            }
        }
    }

    /// A directory record's key has the name behind a length and a hash, or
    /// behind a length alone; either way the name is NUL-ended and ends the key.
    #[test]
    fn a_directory_records_name_is_read_from_either_key() {
        let hashed = |len_and_hash: u32, name: &[u8]| {
            key(2, J_DREC, &[&len_and_hash.to_le_bytes()[..], name].concat())
        };
        let plain =
            |len: u16, name: &[u8]| key(2, J_DREC, &[&len.to_le_bytes()[..], name].concat());
        // The hash is the 22 bits above the length.
        assert_eq!(
            drec_name(&hashed(0xABCD_E000 | 6, b"hello\0")).as_deref(),
            Some("hello")
        );
        assert_eq!(drec_name(&plain(6, b"hello\0")).as_deref(), Some("hello"));
        assert_eq!(drec_name(&plain(1, b"\0")).as_deref(), Some(""));
        // A length that is not the rest of the key is no name.
        assert_eq!(drec_name(&hashed(9, b"hello\0")), None);
        assert_eq!(drec_name(&plain(7, b"hello\0")), None);
        assert_eq!(drec_name(&[0; 8]), None);
        // Not UTF-8: kept as far as it can be.
        assert_eq!(
            drec_name(&plain(3, &[b'a', 0xff, 0])).as_deref(),
            Some("a\u{fffd}")
        );
    }

    #[test]
    fn the_checksum_is_apples() {
        // Worked by hand: words 1 and 2.
        let m = 0xFFFF_FFFFu64;
        assert_eq!(fletcher64(&[1, 0, 0, 0, 2, 0, 0, 0]), 4 << 32 | (m - 7));
        // A block with the checksum it carries reads; with one byte changed, not.
        let b = seal((0..BS).map(|i| (i % 251) as u8).collect());
        assert_eq!(le64(&b, 0), fletcher64(&b[8..]));
    }

    #[test]
    fn the_object_map_gives_the_newest_mapping_not_past_the_transaction() {
        let mut c = Cont::new();
        let omap = c.omap(&[
            mapping(7, 3, 100, 0),
            mapping(7, 5, 200, 0),
            mapping(7, 9, 300, 0),
            mapping(8, 4, 400, 0),
            mapping(8, 6, 400, 1),
            mapping(9, 2, 500, 0),
        ]);
        let img = c.blocks.concat();
        let mut cur = Cursor::new(img);
        let mut v = Vol {
            disk: &mut cur,
            len: (c.blocks.len() * BS) as u64,
            max: 1 << 20,
        };
        let mut fs = Fs {
            v: &mut v,
            block: BS as u64,
            cache: HashMap::new(),
            strict: false,
        };
        let m = load_omap(&mut fs, omap, 6).unwrap();
        // 7: the newest not past 6 is 5. 8: its newest, 6, is a deletion.
        assert_eq!(m.get(&7), Some(&Some(200)));
        assert_eq!(m.get(&8), Some(&None));
        assert_eq!(m.get(&9), Some(&Some(500)));
    }
}
