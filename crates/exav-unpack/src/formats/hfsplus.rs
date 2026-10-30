//! HFS+ and HFSX: the files of a volume, read where they lie.
//!
//! The volume is a `Read + Seek`, read where the walk goes: the volume header,
//! the catalog's nodes, and each file's extents. Only a file is ever held,
//! bounded by the buffer limit.
//!
//! A scanner wants every file's bytes, not a navigable tree, so the catalog
//! B-tree is read once through its leaves, which are chained in key order, and
//! the paths are rebuilt from the folder records. Nothing is searched by name:
//! the case folding that HFS+ lookups need is not here, and an HFSX volume
//! reads the same as an HFS+ one. What is searched, by binary keys, is the
//! extents overflow tree (the extents of a fragmented file past its eighth)
//! and the attributes tree (the `com.apple.decmpfs` attribute of a compressed
//! file, read by `formats/decmpfs`).
//!
//! ```text
//! volume header (1024 bytes in)   block size, the five special forks
//!   catalog file                  B-tree: a folder record or a file record
//!                                 per (parent id, name); a file record holds
//!                                 the data fork and the resource fork
//!   extents overflow file         B-tree: the extents past a fork's eighth
//!   attributes file               B-tree: extended attributes
//! ```
//!
//! All fields are big-endian. Implemented from Apple's TN1150.
//!
//! A file's resource fork is not content here unless it carries a compressed
//! file's bytes: any other is reported, and the data fork is read all the
//! same. A symbolic link is not read. A journal is not replayed.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use super::decmpfs;
use super::vol::{
    Attrs, Emit, Found, Got, List, Piece, Pieces, Vol, be16, be32, be64, hand, read_file,
};
use crate::{Budget, Entry, LimitHit};

/// The catalog id of the root folder, whose children the paths start from.
const ROOT: u32 = 2;

/// Deeper than any real tree: a node's height counts down to a leaf's 1.
const MAX_HEIGHT: u8 = 16;

/// The most folders a path passes through.
const MAX_PATH_DEPTH: usize = 256;

/// The most lookups in the extents overflow tree for the extents of one fork:
/// each gives up to eight, so a fork in this many fragments is not followed
/// to its end.
const MAX_OVERFLOW_LOOKUPS: u32 = 1 << 16;

/// The most an attribute read from its fork is, bytes.
const ATTR_MAX: u64 = 1 << 16;

/// A fork type in an extents overflow key.
const DATA: u8 = 0x00;
const RESOURCE: u8 = 0xFF;

/// `S_IFMT` and `S_IFLNK` of a file's mode.
const S_IFMT: u16 = 0o170000;
const S_IFLNK: u16 = 0o120000;

/// A run of allocation blocks.
#[derive(Clone, Copy, Default)]
struct Extent {
    start: u32,
    count: u32,
}

/// A fork's size and its first eight extents, as a catalog record or the
/// volume header holds them.
#[derive(Clone, Default)]
struct Fork {
    size: u64,
    extents: [Extent; 8],
}

impl Fork {
    /// The fork data (80 bytes) at `at`.
    fn parse(d: &[u8], at: usize) -> Fork {
        let mut fork = Fork {
            size: be64(d, at),
            ..Fork::default()
        };
        for (i, e) in fork.extents.iter_mut().enumerate() {
            let o = at.saturating_add(16).saturating_add(i.saturating_mul(8));
            *e = Extent {
                start: be32(d, o),
                count: be32(d, o.saturating_add(4)),
            };
        }
        fork
    }
}

/// The blocks of a fork in order, which map a position in it to the volume.
struct Map {
    block: u64,
    /// (the fork's block this extent starts at, the extent)
    list: Vec<(u64, Extent)>,
    blocks: u64,
}

impl Map {
    fn new(block: u64) -> Self {
        Map {
            block,
            list: Vec::new(),
            blocks: 0,
        }
    }

    fn push(&mut self, e: Extent) {
        if e.count > 0 {
            self.list.push((self.blocks, e));
            self.blocks = self.blocks.saturating_add(u64::from(e.count));
        }
    }

    /// The bytes the extents hold.
    fn bytes(&self) -> u64 {
        self.blocks.saturating_mul(self.block)
    }

    /// Append `len` bytes of the fork from `off` to `out`. False when the
    /// extents do not hold them or the volume does not have them; what was
    /// appended before that stays.
    fn read(&self, v: &mut Vol, off: u64, len: usize, out: &mut Vec<u8>) -> bool {
        let Some(end) = off.checked_add(len as u64) else {
            return false;
        };
        if end > self.bytes() {
            return false;
        }
        let mut pos = off;
        while pos < end {
            let at = self
                .list
                .partition_point(|(first, _)| *first <= pos.checked_div(self.block).unwrap_or(0));
            let Some((first, e)) = at.checked_sub(1).and_then(|i| self.list.get(i)) else {
                return false;
            };
            let into = pos.saturating_sub(first.saturating_mul(self.block));
            let room = u64::from(e.count)
                .saturating_mul(self.block)
                .saturating_sub(into);
            let take = end.saturating_sub(pos).min(room);
            let Some(phys) = u64::from(e.start)
                .saturating_mul(self.block)
                .checked_add(into)
            else {
                return false;
            };
            if take == 0 || !v.append(phys, crate::bytes::to_usize(take), out) {
                return false;
            }
            pos = pos.saturating_add(take);
        }
        true
    }
}

/// A node of a B-tree: its descriptor and its records.
struct Node {
    data: Vec<u8>,
    kind: u8,
    height: u8,
    next: u32,
    count: usize,
}

const LEAF: u8 = 0xFF;
const INDEX: u8 = 0x00;

impl Node {
    fn parse(data: Vec<u8>) -> Option<Node> {
        let count = usize::from(be16(&data, 10));
        // The offset table, one more entry than there are records, ends the node.
        let table = count.checked_add(1)?.checked_mul(2)?;
        if data.len() < table.checked_add(14)? {
            return None;
        }
        Some(Node {
            kind: *data.get(8)?,
            height: *data.get(9)?,
            next: be32(&data, 0),
            count,
            data,
        })
    }

    /// Record `i`, which lies between its offset and the next record's.
    fn rec(&self, i: usize) -> Option<&[u8]> {
        if i >= self.count {
            return None;
        }
        let size = self.data.len();
        let offset = |k: usize| {
            let at = size.checked_sub(k.checked_add(1)?.checked_mul(2)?)?;
            Some(usize::from(be16(&self.data, at)))
        };
        let (start, end) = (offset(i)?, offset(i.checked_add(1)?)?);
        let table = size.checked_sub(self.count.checked_add(1)?.checked_mul(2)?)?;
        if start < 14 || start > end || end > table {
            return None;
        }
        self.data.get(start..end)
    }
}

/// The offset of what follows a record's key: its `u16` length, and the
/// key, padded to an even length.
fn after_key(rec: &[u8]) -> usize {
    usize::from(be16(rec, 0)).saturating_add(3) & !1
}

/// A B-tree file: the catalog, the extents overflow file or the attributes
/// file.
struct Tree {
    map: Map,
    node_size: usize,
    root: u32,
    height: u8,
    first_leaf: u32,
}

impl Tree {
    /// The tree in the fork `map` describes, from its header node.
    fn open(v: &mut Vol, map: Map) -> Option<Tree> {
        let mut head = Vec::new();
        if !map.read(v, 0, 64, &mut head) || head.get(8) != Some(&1) {
            return None;
        }
        let node_size = usize::from(be16(&head, 32));
        if !(512..=32768).contains(&node_size) || !node_size.is_power_of_two() {
            return None;
        }
        let height = u8::try_from(be16(&head, 14)).ok()?;
        (height <= MAX_HEIGHT).then_some(Tree {
            node_size,
            root: be32(&head, 16),
            height,
            first_leaf: be32(&head, 24),
            map,
        })
    }

    fn node(&self, v: &mut Vol, n: u32) -> Option<Node> {
        let size = self.node_size as u64;
        let mut data = Vec::new();
        self.map
            .read(
                v,
                u64::from(n).checked_mul(size)?,
                self.node_size,
                &mut data,
            )
            .then_some(())?;
        Node::parse(data)
    }

    /// The record `cmp` finds equal, where `cmp` orders a record by its key
    /// against the one wanted. The descent takes, in an index node, the last
    /// record whose key is not past the wanted one.
    fn find(&self, v: &mut Vol, cmp: &dyn Fn(&[u8]) -> Ordering) -> Option<Vec<u8>> {
        let (mut n, mut height) = (self.root, self.height);
        while n != 0 {
            let node = self.node(v, n)?;
            if node.height != height {
                return None;
            }
            let recs = (0..node.count).map(|i| node.rec(i));
            if node.kind == LEAF && height == 1 {
                for rec in recs {
                    match cmp(rec?) {
                        Ordering::Equal => return rec.map(<[u8]>::to_vec),
                        Ordering::Greater => return None,
                        Ordering::Less => {}
                    }
                }
                return None;
            }
            if node.kind != INDEX || height < 2 {
                return None;
            }
            let mut child = None;
            for rec in recs {
                let rec = rec?;
                if cmp(rec) == Ordering::Greater {
                    break;
                }
                child = Some(be32(rec, after_key(rec)));
            }
            n = child?;
            height = height.saturating_sub(1);
        }
        None
    }

    /// Every record of the leaves, in order, until `each` returns false. False
    /// where the tree is damaged: a leaf that is not one, one that cannot be
    /// read, a chain longer than the file holds nodes.
    fn scan(&self, v: &mut Vol, mut each: impl FnMut(&[u8]) -> bool) -> bool {
        let limit = self.map.bytes().checked_div(self.node_size as u64);
        let (mut n, mut seen) = (self.first_leaf, 0u64);
        // A chain that loops back on itself is as long as the volume's size
        // allows (billions of nodes), so it is looked for: the node taken at
        // each power of two of the steps, and met again, is a loop (Brent's).
        let (mut mark, mut power, mut since) = (0u32, 1u64, 0u64);
        while n != 0 {
            seen = seen.saturating_add(1);
            if Some(seen) > limit || n == mark {
                return false;
            }
            since = since.saturating_add(1);
            if since == power {
                (mark, power, since) = (n, power.saturating_mul(2), 0);
            }
            let Some(node) = self.node(v, n) else {
                return false;
            };
            if node.kind != LEAF {
                return false;
            }
            for i in 0..node.count {
                let Some(rec) = node.rec(i) else {
                    return false;
                };
                if !each(rec) {
                    return true;
                }
            }
            n = node.next;
        }
        true
    }
}

/// A file of the catalog.
struct File {
    id: u32,
    parent: u32,
    name: String,
    /// Marked as compressed (decmpfs), as macOS marks one.
    compressed: bool,
    data: Fork,
    resource: Fork,
}

/// What the catalog holds: the folders by id, and the files in key order.
#[derive(Default)]
struct Catalog {
    folders: HashMap<u32, (u32, String)>,
    files: Vec<File>,
}

impl Catalog {
    /// Keep the folder or file record `rec` (a key and its body), unless it
    /// is another kind of record or a symbolic link.
    fn add(&mut self, rec: &[u8]) {
        // The key: its length, the parent's id, the name's length and the
        // name in UTF-16, all inside the key's length.
        let name_len = usize::from(be16(rec, 6));
        let name_bytes = name_len.saturating_mul(2);
        let in_key = usize::from(be16(rec, 0)) >= name_bytes.saturating_add(6);
        let Some(units) =
            crate::bytes::at(rec, 8, name_bytes).filter(|_| in_key && name_len <= 255)
        else {
            return;
        };
        let units: Vec<u16> = units
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        let name = String::from_utf16_lossy(&units);
        let parent = be32(rec, 2);
        let Some(body) = rec.get(after_key(rec)..) else {
            return;
        };
        match be16(body, 0) {
            1 if body.len() >= 88 => {
                self.folders.insert(be32(body, 8), (parent, name));
            }
            2 if body.len() >= 248 && be16(body, 42) & S_IFMT != S_IFLNK => {
                let owner_flags = u32::from(body.get(41).copied().unwrap_or(0));
                self.files.push(File {
                    id: be32(body, 8),
                    parent,
                    name,
                    compressed: owner_flags & decmpfs::COMPRESSED_FLAG != 0,
                    data: Fork::parse(body, 88),
                    resource: Fork::parse(body, 168),
                });
            }
            _ => {}
        }
    }

    /// The path of `name` in folder `parent`, from the root. A folder whose
    /// chain does not reach the root (a record missing, or a loop) stands
    /// where the chain broke, by its id.
    fn path(&self, parent: u32, name: &str) -> String {
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
        let lost = (at != ROOT).then(|| format!("<hfs-folder-{at}>"));
        parts.extend(lost.as_deref());
        parts.reverse();
        format!("/{}", parts.join("/"))
    }
}

/// The volume's trees and geometry.
struct Hfs {
    block: u64,
    extents: Tree,
    attributes: Option<Tree>,
}

/// The extents overflow key `rec` against (`id`, `fork`, `start`): file id
/// first, then fork type, then the fork's block the extents start at.
fn cmp_extent_key(rec: &[u8], id: u32, fork: u8, start: u32) -> Ordering {
    be32(rec, 4)
        .cmp(&id)
        .then(rec.get(2).copied().unwrap_or(0).cmp(&fork))
        .then(be32(rec, 8).cmp(&start))
}

/// The attributes key `rec` against (`id`, `name`): file id, then the name by
/// 16-bit code units, then the first block (0 for a value held whole).
fn cmp_attr_key(rec: &[u8], id: u32, name: &[u16]) -> Ordering {
    let len = usize::from(be16(rec, 12));
    let mine = (0..len).map(|i| be16(rec, 14usize.saturating_add(i.saturating_mul(2))));
    be32(rec, 4)
        .cmp(&id)
        .then_with(|| mine.cmp(name.iter().copied()))
        .then(be32(rec, 8).cmp(&0))
}

impl Hfs {
    /// The blocks of a fork: its eight extents and, past them, the extents
    /// the overflow tree has for (`id`, `fork`).
    fn map(&self, v: &mut Vol, fork: &Fork, id: u32, ty: u8) -> Map {
        let mut map = Map::new(self.block);
        for e in fork.extents {
            map.push(e);
        }
        let need = fork.size.div_ceil(self.block);
        for _ in 0..MAX_OVERFLOW_LOOKUPS {
            if map.blocks >= need {
                break;
            }
            let Ok(start) = u32::try_from(map.blocks) else {
                break;
            };
            let found = self
                .extents
                .find(v, &|rec| cmp_extent_key(rec, id, ty, start));
            // The key is 10 bytes, then eight extents.
            let Some(rec) = found.filter(|r| r.len() >= 76) else {
                break;
            };
            let before = map.blocks;
            for i in 0..8usize {
                let o = 12usize.saturating_add(i.saturating_mul(8));
                map.push(Extent {
                    start: be32(&rec, o),
                    count: be32(&rec, o.saturating_add(4)),
                });
            }
            if map.blocks == before {
                break;
            }
        }
        map
    }

    /// The whole of a fork, or `None` when it is longer than `bound` or its
    /// extents do not give it.
    fn read_fork(&self, v: &mut Vol, fork: &Fork, id: u32, ty: u8, bound: u64) -> Option<Vec<u8>> {
        if fork.size > bound {
            return None;
        }
        let mut out = Vec::new();
        let len = crate::bytes::to_usize(fork.size);
        self.map(v, fork, id, ty)
            .read(v, 0, len, &mut out)
            .then_some(out)
    }

    /// The `com.apple.decmpfs` attribute of file `id`.
    fn decmpfs_attr(&self, v: &mut Vol, id: u32) -> Option<Vec<u8>> {
        let tree = self.attributes.as_ref()?;
        let name: Vec<u16> = decmpfs::ATTR.encode_utf16().collect();
        let rec = tree.find(v, &|rec| cmp_attr_key(rec, id, &name))?;
        let value = rec.get(after_key(&rec)..)?;
        match be32(value, 0) {
            // recordType, two reserved words, the size, the bytes
            0x10 => {
                let len = usize::try_from(be32(value, 12)).ok()?;
                crate::bytes::at(value, 16, len).map(<[u8]>::to_vec)
            }
            // recordType, a reserved word, the fork data
            0x20 => {
                let fork = Fork::parse(value, 8);
                // Its eight extents only: an attribute this long is not one.
                let mut map = Map::new(self.block);
                for e in fork.extents {
                    map.push(e);
                }
                let mut out = Vec::new();
                let len = crate::bytes::to_usize(fork.size.min(ATTR_MAX));
                (fork.size <= ATTR_MAX && map.read(v, 0, len, &mut out)).then_some(out)
            }
            _ => None,
        }
    }
}

impl Hfs {
    /// The bytes of `f`: held when they are at most `cap`, else read as they
    /// go. A compressed file is unpacked, and is not read as it goes.
    fn file<'a>(&self, v: &'a mut Vol<'_>, f: &File, cap: u64) -> Got<'a> {
        if f.compressed {
            if let Some(attr) = self.decmpfs_attr(v, f.id) {
                let kind = decmpfs::header(&attr).map(|h| h.kind);
                let fork = kind
                    .filter(|&k| decmpfs::in_fork(k))
                    // A fork holds the bytes in blocks, a little over their number.
                    .and_then(|_| {
                        let bound = cap.saturating_add(cap / 32).saturating_add(4096);
                        self.read_fork(v, &f.resource, f.id, RESOURCE, bound)
                    });
                return decmpfs::unpack(&attr, fork.as_deref(), cap);
            }
            if f.data.size == 0 {
                return Got::Why("compressed file (decmpfs) without its attribute");
            }
        }
        let map = self.map(v, &f.data, f.id, DATA);
        let block = self.block;
        let plan = List {
            pieces: map
                .list
                .iter()
                .map(|(_, e)| {
                    Piece::Disk(
                        u64::from(e.start).saturating_mul(block),
                        u64::from(e.count).saturating_mul(block),
                    )
                })
                .collect::<Vec<_>>()
                .into_iter(),
            // The extents hold what the fork says it does.
            intact: map.bytes() >= f.data.size,
        };
        read_file(v, Pieces::new(plan, f.data.size), f.data.size, cap)
    }
}

/// Whether `head`, the start of a volume, holds the header of an HFS+ or an
/// HFSX volume (version 4 and 5).
pub(crate) fn is_hfsplus(head: &[u8]) -> bool {
    matches!(
        (be16(head, 1024), be16(head, 1026)),
        (0x482B, 4) | (0x4858, 5)
    )
}

/// Walk the HFS+ or HFSX volume `disk`, which starts at its boot area,
/// handing each file to `visit`.
pub(crate) fn walk_volume<D: Read + Seek, R>(
    mut disk: D,
    budget: &mut Budget,
    visit: Emit<R>,
) -> Result<Option<R>, LimitHit> {
    let len = disk
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("HFS+ volume: {e}")))?;
    let max = crate::bytes::to_usize(budget.limits().max_buffer_bytes);
    let mut v = Vol {
        disk: &mut disk,
        len,
        max,
    };
    let Some((hfs, catalog)) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "hfs+ open: the volume header or a tree is unreadable".into(),
        ));
    };

    // The catalog, kept up to the member limit; a volume with more is walked
    // as far as that and then stops as any container does at the limit.
    let limit = crate::bytes::to_usize(budget.limits().max_members);
    let mut cat = Catalog::default();
    let mut capped = false;
    let intact = catalog.scan(&mut v, |rec| {
        if cat.files.len().saturating_add(cat.folders.len()) >= limit {
            capped = true;
            return false;
        }
        cat.add(rec);
        true
    });

    for f in &cat.files {
        let path = cat.path(f.parent, &f.name);
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let got = hfs.file(&mut v, f, cap);
        // A compressed file's resource fork is its content, not a fork to report.
        if f.resource.size > 0 && !f.compressed {
            let note = Entry::unsupported(path.clone(), 0, false, "HFS+ resource fork not read");
            if let Some(r) = visit(Found::Held(note), budget) {
                return Ok(Some(r));
            }
            // A file that is only a resource fork has nothing else to give.
            if f.data.size == 0 {
                continue;
            }
        }
        if let Some(r) = hand(budget, &mut *visit, path, Attrs::default(), got) {
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
            "hfs+ walk: catalog damaged; the files before the damage were scanned".into(),
        ));
    }
    Ok(None)
}

/// The volume's header and trees.
fn open(v: &mut Vol) -> Option<(Hfs, Tree)> {
    let h = v.at(1024, 512)?;
    let (sig, version) = (be16(&h, 0), be16(&h, 2));
    // "H+" is version 4, "HX" (case-sensitive) version 5.
    if !matches!((sig, version), (0x482B, 4) | (0x4858, 5)) {
        return None;
    }
    let block = be32(&h, 40);
    if block < 512 || !block.is_power_of_two() || block > 1 << 30 {
        return None;
    }
    let block = u64::from(block);
    // Nothing is read from past the volume the header describes.
    v.len = v.len.min(u64::from(be32(&h, 44)).saturating_mul(block));

    let inline = |at: usize| {
        let fork = Fork::parse(&h, at);
        let mut map = Map::new(block);
        for e in fork.extents {
            map.push(e);
        }
        (fork, map)
    };
    // The extents file has no overflow of its own: its extents are the eight.
    let (_, map) = inline(192);
    let mut hfs = Hfs {
        block,
        extents: Tree::open(v, map)?,
        attributes: None,
    };
    let catalog = Fork::parse(&h, 272);
    let map = hfs.map(v, &catalog, 4, DATA);
    let catalog = Tree::open(v, map)?;
    let attributes = Fork::parse(&h, 352);
    if attributes.size > 0 {
        let map = hfs.map(v, &attributes, 8, DATA);
        hfs.attributes = Tree::open(v, map);
    }
    Some((hfs, catalog))
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::super::vol::collected;
    use super::*;
    use crate::Limits;
    use std::io::{Cursor, Write};

    /// The allocation block and the node size of the volumes built here.
    const B: usize = 512;

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// The fork data (80 bytes) of `size` bytes in `(start, count)` extents.
    fn fork(size: u64, extents: &[(u32, u32)]) -> Vec<u8> {
        let mut f = size.to_be_bytes().to_vec();
        f.extend_from_slice(&[0; 8]);
        for i in 0..8 {
            let (s, c) = extents.get(i).copied().unwrap_or((0, 0));
            f.extend_from_slice(&be32(s));
            f.extend_from_slice(&be32(c));
        }
        f
    }

    /// A catalog key: the parent's id, the name.
    fn key(parent: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut k = be16((6 + 2 * units.len()) as u16).to_vec();
        k.extend_from_slice(&be32(parent));
        k.extend_from_slice(&be16(units.len() as u16));
        k.extend(units.iter().flat_map(|u| u.to_be_bytes()));
        k
    }

    fn folder(parent: u32, name: &str, id: u32) -> Vec<u8> {
        let mut r = key(parent, name);
        let mut body = vec![0u8; 88];
        body[..2].copy_from_slice(&be16(1));
        body[8..12].copy_from_slice(&be32(id));
        r.extend(body);
        r
    }

    /// A file record: `mode`, the owner flags, the data fork and the resource
    /// fork (each 80 bytes).
    fn file(
        parent: u32,
        name: &str,
        id: u32,
        mode: u16,
        flags: u8,
        data: &[u8],
        rsrc: &[u8],
    ) -> Vec<u8> {
        let mut r = key(parent, name);
        let mut body = vec![0u8; 248];
        body[..2].copy_from_slice(&be16(2));
        body[8..12].copy_from_slice(&be32(id));
        body[41] = flags;
        body[42..44].copy_from_slice(&be16(mode));
        body[88..168].copy_from_slice(data);
        body[168..248].copy_from_slice(rsrc);
        r.extend(body);
        r
    }

    /// The size of the nodes: a file record fills a node of the smallest size.
    const N: usize = 4096;

    /// A node holding `recs`.
    fn node(kind: u8, height: u8, next: u32, recs: &[Vec<u8>]) -> Vec<u8> {
        let mut n = vec![0u8; N];
        n[..4].copy_from_slice(&be32(next));
        n[8] = kind;
        n[9] = height;
        n[10..12].copy_from_slice(&be16(recs.len() as u16));
        let mut at = 14;
        let mut offsets = Vec::new();
        for r in recs {
            n[at..at + r.len()].copy_from_slice(r);
            offsets.push(at);
            at += r.len();
        }
        offsets.push(at);
        for (i, o) in offsets.iter().enumerate() {
            n[N - 2 * (i + 1)..N - 2 * i].copy_from_slice(&be16(*o as u16));
        }
        n
    }

    fn leaf(next: u32, recs: &[Vec<u8>]) -> Vec<u8> {
        node(0xFF, 1, next, recs)
    }

    /// The file of a tree: its header node, then `nodes`.
    fn tree(depth: u16, root: u32, first_leaf: u32, nodes: &[Vec<u8>]) -> Vec<u8> {
        let mut h = node(1, 0, 0, &[]);
        h[14..16].copy_from_slice(&be16(depth));
        h[16..20].copy_from_slice(&be32(root));
        h[24..28].copy_from_slice(&be32(first_leaf));
        h[32..34].copy_from_slice(&be16(N as u16));
        h[36..40].copy_from_slice(&be32(nodes.len() as u32 + 1));
        let mut t = h;
        for n in nodes {
            t.extend_from_slice(n);
        }
        t
    }

    /// A volume of 512-byte blocks being laid out: the boot area, the header's
    /// block, then what is added.
    struct Img {
        d: Vec<u8>,
    }

    impl Img {
        fn new() -> Img {
            Img { d: vec![0; 3 * B] }
        }

        /// `bytes` in blocks of their own: (the first block, how many).
        fn add(&mut self, bytes: &[u8]) -> (u32, u32) {
            let start = (self.d.len() / B) as u32;
            self.d.extend_from_slice(bytes);
            self.d.resize(self.d.len().div_ceil(B) * B, 0);
            (start, (self.d.len() / B) as u32 - start)
        }

        /// A fork holding `bytes`, in one extent.
        fn data(&mut self, bytes: &[u8]) -> Vec<u8> {
            let (s, c) = self.add(bytes);
            fork(bytes.len() as u64, &[(s, c)])
        }

        /// The volume: the three trees (each the file `tree` made) and the
        /// header over them.
        fn finish(mut self, catalog: &[u8], extents: &[u8], attributes: &[u8]) -> Vec<u8> {
            let mut forks = Vec::new();
            // Every volume has an extents file, a tree with no records at least.
            let empty = tree(0, 0, 0, &[]);
            let extents = if extents.is_empty() { &empty } else { extents };
            for t in [extents, catalog, attributes] {
                let f = match t.is_empty() {
                    true => fork(0, &[]),
                    false => {
                        let (s, c) = self.add(t);
                        fork(t.len() as u64, &[(s, c)])
                    }
                };
                forks.push(f);
            }
            let total = (self.d.len() / B) as u32;
            let h = &mut self.d[1024..1536];
            h[..2].copy_from_slice(b"H+");
            h[2..4].copy_from_slice(&be16(4));
            h[40..44].copy_from_slice(&be32(B as u32));
            h[44..48].copy_from_slice(&be32(total));
            h[192..272].copy_from_slice(&forks[0]);
            h[272..352].copy_from_slice(&forks[1]);
            h[352..432].copy_from_slice(&forks[2]);
            self.d
        }
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

    const FILE: u16 = 0o100644;
    const LINK: u16 = 0o120777;

    /// A volume of folders and files in two chained leaves of the catalog.
    fn tree_of_folders() -> Vec<u8> {
        let mut img = Img::new();
        let (a, b, c) = (
            img.data(b"in root"),
            img.data(b"in dir"),
            img.data(b"in sub"),
        );
        let none = fork(0, &[]);
        let first = [
            folder(1, "Vol", 2),
            file(2, "a.txt", 20, FILE, 0, &a, &none),
            folder(2, "dir", 16),
            file(2, "link", 23, LINK, 0, &none, &none),
        ];
        let second = [
            file(16, "b.txt", 21, FILE, 0, &b, &none),
            folder(16, "sub", 17),
            file(17, "c.txt", 22, FILE, 0, &c, &none),
        ];
        let cat = tree(1, 1, 1, &[leaf(2, &first), leaf(0, &second)]);
        img.finish(&cat, &tree(0, 0, 0, &[]), &[])
    }

    #[test]
    fn the_files_of_a_tree_of_folders_come_out_under_their_paths() {
        let (entries, end) = run(&tree_of_folders(), Limits::default());
        assert!(end.is_ok());
        // The symbolic link is not read; the leaves are walked in their chain.
        assert_eq!(
            named(&entries),
            [
                ("/a.txt", &b"in root"[..]),
                ("/dir/b.txt", b"in dir"),
                ("/dir/sub/c.txt", b"in sub"),
            ]
        );
    }

    #[test]
    fn a_file_in_a_folder_the_catalog_lacks_is_named_by_the_folder_it_lost() {
        let mut img = Img::new();
        let data = img.data(b"x");
        let none = fork(0, &[]);
        let recs = [
            folder(1, "Vol", 2),
            // Folders 50 and 51 are each other's parent: a loop.
            folder(51, "f50", 50),
            folder(50, "f51", 51),
            file(99, "orphan", 30, FILE, 0, &data, &none),
            file(50, "looped", 31, FILE, 0, &data, &none),
        ];
        let cat = tree(1, 1, 1, &[leaf(0, &recs)]);
        let (entries, end) = run(&img.finish(&cat, &[], &[]), Limits::default());
        assert!(end.is_ok());
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names[0], "/<hfs-folder-99>/orphan");
        // The loop ends where the path depth does, and says where it broke.
        assert!(names[1].starts_with("/<hfs-folder-5"), "{}", names[1]);
        assert!(names[1].ends_with("/looped"));
    }

    /// The extents past a fork's eighth are in the extents overflow tree, found
    /// through its index.
    #[test]
    fn a_fragmented_file_is_put_together_from_the_overflow_tree() {
        let mut img = Img::new();
        // Twelve blocks of one file, each between two blocks of another.
        let pieces: Vec<Vec<u8>> = (0..12u8).map(|i| vec![b'a' + i; B]).collect();
        let mut at = Vec::new();
        for p in &pieces {
            at.push(img.add(p));
            img.add(&[0xee; B]);
        }
        let want: Vec<u8> = pieces.concat();
        let inline: Vec<(u32, u32)> = at[..8].to_vec();
        let data = fork(want.len() as u64, &inline);
        let none = fork(0, &[]);

        let ext_rec = |id: u32, start: u32, exts: &[(u32, u32)]| {
            let mut r = be16(10).to_vec();
            r.extend_from_slice(&[0, 0]);
            r.extend_from_slice(&be32(id));
            r.extend_from_slice(&be32(start));
            r.extend_from_slice(&fork(0, exts)[16..]);
            r
        };
        // Records for other files before and after, in two leaves under an index.
        let other = |id| ext_rec(id, 0, &[(1, 1)]);
        let ours = ext_rec(30, 8, &at[8..]);
        let first = leaf(2, &[other(5), other(29)]);
        let second = leaf(0, &[ours.clone(), other(31)]);
        let index = node(
            0,
            2,
            0,
            &[
                [&other(5)[..12], &be32(1)].concat(),
                [&ours[..12], &be32(2)].concat(),
            ],
        );
        let extents = tree(2, 3, 1, &[first, second, index]);

        let cat = tree(
            1,
            1,
            1,
            &[leaf(
                0,
                &[folder(1, "V", 2), file(2, "f", 30, FILE, 0, &data, &none)],
            )],
        );
        let (entries, end) = run(&img.finish(&cat, &extents, &[]), Limits::default());
        assert!(end.is_ok());
        assert_eq!(named(&entries), [("/f", &want[..])]);
    }

    /// An attribute record: file id, name, inline value.
    fn attr(id: u32, name: &str, value: &[u8]) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut r = be16((12 + 2 * units.len()) as u16).to_vec();
        r.extend_from_slice(&[0, 0]);
        r.extend_from_slice(&be32(id));
        r.extend_from_slice(&be32(0));
        r.extend_from_slice(&be16(units.len() as u16));
        r.extend(units.iter().flat_map(|u| u.to_be_bytes()));
        if r.len() % 2 == 1 {
            r.push(0);
        }
        r.extend_from_slice(&be32(0x10));
        r.extend_from_slice(&[0; 8]);
        r.extend_from_slice(&be32(value.len() as u32));
        r.extend_from_slice(value);
        r
    }

    fn deflated(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn decmpfs_attr(kind: u32, size: usize, payload: &[u8]) -> Vec<u8> {
        let mut a = b"fpmc".to_vec();
        a.extend_from_slice(&kind.to_le_bytes());
        a.extend_from_slice(&(size as u64).to_le_bytes());
        a.extend_from_slice(payload);
        a
    }

    /// Files macOS compressed have no data fork. Their bytes are in the
    /// `com.apple.decmpfs` attribute, found by its file id and name among
    /// the others in the attributes tree, or in the resource fork.
    #[test]
    fn compressed_files_are_unpacked_from_their_attribute_or_resource_fork() {
        let mut img = Img::new();
        let text = b"compressed text, compressed text, compressed text".to_vec();
        let none = fork(0, &[]);

        // Type 4: one zlib block, the table 4 bytes into the fork.
        let z = deflated(&text);
        let mut rsrc = vec![0, 0, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0];
        rsrc.extend_from_slice(&(z.len() as u32).to_le_bytes());
        rsrc.extend_from_slice(&z);
        let rsrc = img.data(&rsrc);

        const PACKED: u8 = 0x20;
        let recs = [
            folder(1, "V", 2),
            file(2, "inline", 40, FILE, PACKED, &none, &none),
            file(2, "forked", 41, FILE, PACKED, &none, &rsrc),
            // Not marked: its attribute is not looked for.
            file(2, "plain", 42, FILE, 0, &img.data(b"plain"), &none),
        ];
        let cat = tree(1, 1, 1, &[leaf(0, &recs)]);
        let inline = decmpfs_attr(3, text.len(), &deflated(&text));
        let forked = decmpfs_attr(4, text.len(), &[]);
        let other = decmpfs_attr(3, 5, &deflated(b"wrong"));
        let first = leaf(
            2,
            &[
                attr(39, "com.apple.decmpfs", &other),
                attr(40, "com.apple.FinderInfo", b"zz"),
            ],
        );
        let second = leaf(
            0,
            &[
                attr(40, "com.apple.decmpfs", &inline),
                attr(41, "com.apple.decmpfs", &forked),
                attr(42, "com.apple.decmpfs", &other),
            ],
        );
        let key_of = |r: &Vec<u8>| r[..2 + usize::from(u16::from_be_bytes([r[0], r[1]]))].to_vec();
        let index = node(
            0,
            2,
            0,
            &[
                [
                    key_of(&attr(39, "com.apple.decmpfs", &[])),
                    be32(1).to_vec(),
                ]
                .concat(),
                [
                    key_of(&attr(40, "com.apple.decmpfs", &[])),
                    be32(2).to_vec(),
                ]
                .concat(),
            ],
        );
        let attrs = tree(2, 3, 1, &[first, second, index]);
        let (entries, end) = run(
            &img.finish(&cat, &tree(0, 0, 0, &[]), &attrs),
            Limits::default(),
        );
        assert!(end.is_ok());
        // The resource fork of a compressed file is its content, not a fork to report.
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
    fn a_compressed_file_whose_attribute_is_missing_is_reported_not_empty() {
        let img = Img::new();
        let none = fork(0, &[]);
        let recs = [
            folder(1, "V", 2),
            file(2, "gone", 40, FILE, 0x20, &none, &none),
        ];
        let cat = tree(1, 1, 1, &[leaf(0, &recs)]);
        let (entries, _) = run(&img.finish(&cat, &[], &[]), Limits::default());
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .unsupported
                .unwrap()
                .contains("without its attribute")
        );
    }

    #[test]
    fn a_resource_fork_is_reported_and_the_data_fork_is_still_read() {
        let mut img = Img::new();
        let data = img.data(b"data fork");
        let rsrc = fork(5, &[]);
        let only = fork(0, &[]);
        let recs = [
            folder(1, "V", 2),
            file(2, "both", 30, FILE, 0, &data, &rsrc),
            file(2, "fork-only", 31, FILE, 0, &only, &rsrc),
        ];
        let cat = tree(1, 1, 1, &[leaf(0, &recs)]);
        let (entries, _) = run(&img.finish(&cat, &[], &[]), Limits::default());
        let got: Vec<_> = entries
            .iter()
            .map(|e| (&e.name[..], e.unsupported, e.data.len()))
            .collect();
        let note = Some("HFS+ resource fork not read");
        assert_eq!(
            got,
            [
                ("/both", note, 0),
                ("/both", None, 9),
                ("/fork-only", note, 0)
            ]
        );
    }

    #[test]
    fn a_file_the_volume_holds_only_part_of_is_reported_with_what_there_is() {
        let mut img = Img::new();
        let (s, _) = img.add(&[7; B]);
        // 1000 bytes declared, one block mapped.
        let data = fork(1000, &[(s, 1)]);
        let recs = [
            folder(1, "V", 2),
            file(2, "short", 30, FILE, 0, &data, &fork(0, &[])),
        ];
        let cat = tree(1, 1, 1, &[leaf(0, &recs)]);
        let (entries, end) = run(&img.finish(&cat, &[], &[]), Limits::default());
        assert!(end.is_ok());
        assert_eq!(
            entries[0].unsupported,
            Some("file could not be read from the volume")
        );
        assert_eq!(entries[0].data, vec![7; B]);
    }

    #[test]
    fn files_past_the_buffer_limit_are_read_as_they_go_across_their_extents() {
        let mut img = Img::new();
        let (first, _) = img.add(&[1; B]);
        let (second, _) = img.add(&[2; B]);
        // The second block of the file is before the first on the volume.
        let data = fork(2 * B as u64, &[(second, 1), (first, 1)]);
        let small = img.data(b"x");
        let none = fork(0, &[]);
        let recs = [
            folder(1, "V", 2),
            file(2, "big", 30, FILE, 0, &data, &none),
            file(2, "small", 31, FILE, 0, &small, &none),
        ];
        let cat = tree(1, 1, 1, &[leaf(0, &recs)]);
        let vol = img.finish(&cat, &[], &[]);
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 100,
            ..Limits::default()
        });
        let (e, end) = collected(|emit| walk_volume(Cursor::new(vol.clone()), &mut budget, emit));
        end.unwrap();
        let (big, was) = e.iter().find(|(m, _)| m.name == "/big").unwrap();
        assert!(*was, "past the limit, so not held");
        assert_eq!(big.data, [vec![2u8; B], vec![1u8; B]].concat());
        let (small, was) = e.iter().find(|(m, _)| m.name == "/small").unwrap();
        assert!(!*was);
        assert_eq!(small.data, b"x");
    }

    #[test]
    fn a_catalog_larger_than_the_member_limit_is_walked_to_it_and_then_stops() {
        let limits = Limits {
            max_members: 3,
            ..Limits::default()
        };
        let (entries, end) = run(&tree_of_folders(), limits);
        // The folder of the volume, "a.txt" and "dir" are the three records
        // kept; what is kept is scanned.
        assert_eq!(named(&entries), [("/a.txt", &b"in root"[..])]);
        let hit = end.expect_err("the member limit");
        assert_eq!(hit.kind, crate::LimitKind::MaxFiles);
    }

    #[test]
    fn a_damaged_leaf_ends_the_walk_after_the_files_before_it() {
        let mut img = tree_of_folders();
        // The catalog is the second tree written: find its second leaf by the
        // names it holds, and make it an index node.
        let at = img
            .windows(12)
            .position(|w| w == [0, 0x10, 0, 0, 0, 0x10, 0, 5, 0, b'b', 0, b'.'])
            .unwrap();
        img[at - 14 + 8] = 0;
        let (entries, end) = run(&img, Limits::default());
        assert_eq!(named(&entries), [("/a.txt", &b"in root"[..])]);
        assert!(end.expect_err("damage").is_corrupt());
    }

    #[test]
    fn nothing_is_a_volume_but_a_header_with_a_block_size_and_trees() {
        let good = tree_of_folders();
        for (at, byte) in [(1024, b'X'), (1027, 9), (1064, 3)] {
            let mut bad = good.clone();
            bad[at] = byte;
            let (entries, end) = run(&bad, Limits::default());
            assert!(entries.is_empty(), "byte {at}");
            assert!(end.expect_err("not a volume").is_corrupt(), "byte {at}");
        }
        assert!(run(&good[..1200], Limits::default()).1.is_err());
    }

    /// Whatever a volume says, the walk ends: every byte of the header and
    /// the trees changed, in turn, to each of a few values.
    #[test]
    fn damaged_volumes_end_the_walk_without_a_panic() {
        let good = tree_of_folders();
        for at in (1024..good.len()).step_by(3) {
            for byte in [0x00, 0x01, 0x7f, 0xff] {
                let mut bad = good.clone();
                bad[at] = byte;
                let _ = run(&bad, Limits::default());
            }
        }
    }

    /// A disk of `image` and then zeros up to `len`: a virtual disk of a size
    /// its header declares and nothing behind.
    struct Padded {
        image: Vec<u8>,
        len: u64,
        at: u64,
    }

    impl Read for Padded {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (buf.len() as u64).min(self.len.saturating_sub(self.at)) as usize;
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = self.image.get(self.at as usize + i).copied().unwrap_or(0);
            }
            self.at += n as u64;
            Ok(n)
        }
    }

    impl std::io::Seek for Padded {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.at = match to {
                SeekFrom::Start(n) => n,
                SeekFrom::End(d) => self.len.saturating_add_signed(d),
                SeekFrom::Current(d) => self.at.saturating_add_signed(d),
            };
            Ok(self.at)
        }
    }

    /// Two leaves that are each other's next, in a catalog whose fork says it
    /// is 32 GiB (a fuzzer's 19 KB disk image of this took 21 s under the
    /// sanitizer, and a declared 2^62 bytes would not end): the chain is
    /// bounded by the fork, 8 million nodes here, and each is a valid leaf with
    /// no record the catalog keeps, so no member limit ends it.
    #[test]
    fn a_leaf_chain_that_loops_is_damage_not_a_walk_to_the_end_of_the_fork() {
        let t = tree(1, 1, 1, &[leaf(2, &[]), leaf(1, &[])]);
        let mut img = Img::new().finish(&t, &[], &[]);
        // The catalog's one extent is 2^26 blocks of 512 bytes, from its start.
        let fork_at = 1024 + 272;
        let extent_count = fork_at + 16 + 4;
        img[extent_count..extent_count + 4].copy_from_slice(&be32(1 << 26));
        img[fork_at..fork_at + 8].copy_from_slice(&(512u64 << 26).to_be_bytes());
        img[1024 + 44..1024 + 48].copy_from_slice(&be32(u32::MAX));
        let disk = Padded {
            image: img,
            len: 1 << 40,
            at: 0,
        };
        let mut budget = Budget::new(Limits::default());
        let started = std::time::Instant::now();
        let end = walk_volume(disk, &mut budget, &mut |_, _| None::<()>);
        assert!(started.elapsed().as_secs() < 2, "{:?}", started.elapsed());
        assert!(end.expect_err("a loop").is_corrupt());
    }
}
