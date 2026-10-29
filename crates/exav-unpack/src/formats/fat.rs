//! FAT12, FAT16 and FAT32: the files of a volume, read where they lie.
//!
//! A disk image handed to a victim is usually mounted, and what they run is a
//! *file* in the filesystem. exav reconstructs the guest disk of every image
//! format it opens, but a raw disk is only a pile of sectors: carving finds a
//! file whose magic sits at the start of a contiguous run, and misses the rest.
//!
//! What that costs, concretely. A FAT image with a zipped payload written to a
//! fresh filesystem is contiguous, and carving reaches it. Write two other files
//! first, delete the middle one, then write the payload: it lands in the hole
//! and continues after, in two runs, and carving finds only the first fragment,
//! which will not decompress. Reassembling that needs the cluster chain, which
//! means reading the filesystem.
//!
//! The volume is a `Read + Seek`, read where the walk goes: the boot sector,
//! the part of the allocation table a chain passes through, each directory's
//! clusters and each file's runs of clusters. Only a file is ever held, bounded
//! by the buffer limit.
//!
//! ```text
//! boot sector          sector and cluster sizes, where the tables start
//!   allocation table   one entry per cluster: the next of its chain, or the end
//!   root directory     a fixed run of sectors (FAT12/16) or a chain (FAT32)
//!   data clusters      32-byte entries in a directory: a name, a first
//!                      cluster and a size
//! ```
//!
//! A long name is the UCS-2 text of the entries before its short one, taken
//! when their checksum is the short name's, as the systems that mount the
//! volume take it; otherwise the short name is the name. A deleted entry and
//! the volume label are not files. The volume boot record is also what a
//! partition table is *not*: see `formats/partition.rs`, where mistaking one for
//! the other invents a partition spanning the whole image.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};

use super::vol::{Attrs, Emit, Got, Next, Piece, Pieces, Plan, Vol, give, le16, le32, read_file};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, LimitHit, Mtime};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// Bytes of the allocation table kept at a time.
const PAGE: u64 = 4096;

/// How many of those are kept.
const PAGES: usize = 64;

/// Attribute bits.
const ATTR_VOLUME: u8 = 0x08;
const ATTR_DIR: u8 = 0x10;
/// Read-only, hidden, system and volume label together mark a long name's part.
const ATTR_LONG: u8 = 0x0F;

/// The characters of CP437, the code page short names are in, from 0x80 on.
const CP437: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

/// Does this look like a FAT volume boot record?
///
/// The signature is the same `55 AA` an MBR ends with, so the BIOS Parameter
/// Block has to carry the weight: a printable OEM name, a sector size that is
/// one of four values, and a cluster size that is a power of two. A filesystem
/// type string in one of its two possible places settles it.
pub(crate) fn is_fat(data: &[u8]) -> bool {
    if data.len() < 512 || data.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return false;
    }
    // A jump instruction begins every boot sector.
    if !matches!(data[0], 0xEB | 0xE9) {
        return false;
    }
    let Some(oem) = data.get(3..11) else {
        return false;
    };
    if !oem.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return false;
    }
    let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
    let sectors_per_cluster = data[13];
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        || sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
    {
        return false;
    }
    // FAT12/16 keep the type string at 54, FAT32 at 82.
    let ty12 = data.get(54..59);
    let ty32 = data.get(82..87);
    matches!(ty12, Some(b"FAT12") | Some(b"FAT16") | Some(b"FAT  "))
        || ty12.map(|t| t.starts_with(b"FAT")).unwrap_or(false)
        || matches!(ty32, Some(b"FAT32"))
}

/// Where a directory is.
#[derive(Clone, Copy)]
enum Dir {
    /// The root of a FAT12/16 volume: a run of sectors before the clusters.
    Root,
    /// A chain of clusters, from this one.
    Chain(u32),
}

/// What an entry of the allocation table says.
enum Link {
    Next(u32),
    End,
    /// Free, bad or out of range: not a chain.
    Broken,
}

/// A file or a directory in a directory.
struct Item {
    name: String,
    dir: bool,
    first: u32,
    size: u32,
    mtime: Option<Mtime>,
}

/// What the boot sector says of the volume.
struct Fat {
    /// Bytes in a cluster.
    cluster: u64,
    /// 12, 16 or 32.
    bits: u32,
    /// Clusters of data, numbered from 2.
    clusters: u32,
    /// Byte offsets of the table in use, of the fixed root directory and of
    /// cluster 2.
    table: u64,
    root: u64,
    root_len: u64,
    data: u64,
    /// The first cluster of a FAT32 root directory.
    root_cluster: u32,
    /// Pages of the table, by number.
    pages: HashMap<u64, Vec<u8>>,
}

impl Fat {
    /// The byte of the table at `off`.
    fn table_byte(&mut self, v: &mut Vol, off: u64) -> Option<u8> {
        let (page, at) = (off.checked_div(PAGE)?, off.checked_rem(PAGE)?);
        if !self.pages.contains_key(&page) {
            let start = page.checked_mul(PAGE)?;
            let want = usize::try_from(PAGE).ok()?;
            let got = v.at(self.table.checked_add(start)?, want).or_else(|| {
                // The end of the volume may cut the last page short.
                let left = v.len.checked_sub(self.table.checked_add(start)?)?;
                v.at(
                    self.table.checked_add(start)?,
                    crate::bytes::to_usize(left.min(PAGE)),
                )
            })?;
            if self.pages.len() >= PAGES {
                self.pages.clear();
            }
            self.pages.insert(page, got);
        }
        self.pages
            .get(&page)?
            .get(crate::bytes::to_usize(at))
            .copied()
    }

    /// The `n` bytes of the table at `off`, as a little-endian number.
    fn entry(&mut self, v: &mut Vol, off: u64, n: u64) -> Option<u32> {
        let mut x = 0u32;
        for i in (0..n).rev() {
            let b = self.table_byte(v, off.checked_add(i)?)?;
            x = x.checked_mul(256)?.checked_add(u32::from(b))?;
        }
        Some(x)
    }

    /// What follows cluster `c` in its chain.
    fn link(&mut self, v: &mut Vol, c: u32) -> Link {
        if c < 2 || c > self.clusters.saturating_add(1) {
            return Link::Broken;
        }
        let at = u64::from(c);
        let raw = match self.bits {
            // Two entries share three bytes.
            12 => self
                .entry(v, at.saturating_add(at / 2), 2)
                .map(|pair| if at % 2 == 1 { pair >> 4 } else { pair & 0xFFF }),
            16 => self.entry(v, at.saturating_mul(2), 2),
            _ => self
                .entry(v, at.saturating_mul(4), 4)
                .map(|x| x & 0x0FFF_FFFF),
        };
        let Some(raw) = raw else {
            return Link::Broken;
        };
        // The values from 0xFF8 (FAT12), 0xFFF8 and 0x0FFFFFF8 on end a chain.
        let end = match self.bits {
            12 => 0xFF8,
            16 => 0xFFF8,
            _ => 0x0FFF_FFF8,
        };
        if raw >= end {
            Link::End
        } else if raw < 2 || raw > self.clusters.saturating_add(1) {
            Link::Broken
        } else {
            Link::Next(raw)
        }
    }

    /// The byte offset of cluster `c`.
    fn at(&self, c: u32) -> Option<u64> {
        u64::from(c.checked_sub(2)?)
            .checked_mul(self.cluster)?
            .checked_add(self.data)
    }

    /// The items of directory `dir`, up to `limit` of them. `left` counts the
    /// clusters of directories the walk may still read. The flag is false
    /// where the directory is damaged.
    fn items(&mut self, v: &mut Vol, dir: Dir, left: &mut u64, limit: usize) -> (Vec<Item>, bool) {
        let mut parse = Parser::default();
        let mut intact = true;
        match dir {
            Dir::Root => {
                let bytes = crate::bytes::to_usize(self.root_len);
                match v.at(self.root, bytes) {
                    Some(block) => {
                        parse.feed(&block, self.bits == 32, limit);
                    }
                    None => intact = false,
                }
            }
            Dir::Chain(first) => {
                let mut c = first;
                let mut steps = 0u64;
                'chain: loop {
                    if *left == 0 || steps >= u64::from(self.clusters) {
                        intact = false;
                        break;
                    }
                    *left = left.saturating_sub(1);
                    steps = steps.saturating_add(1);
                    let block = self
                        .at(c)
                        .and_then(|o| v.at(o, crate::bytes::to_usize(self.cluster)));
                    let Some(block) = block else {
                        intact = false;
                        break;
                    };
                    if parse.feed(&block, self.bits == 32, limit) {
                        break 'chain;
                    }
                    match self.link(v, c) {
                        Link::Next(next) => c = next,
                        Link::End => break,
                        Link::Broken => {
                            intact = false;
                            break;
                        }
                    }
                }
            }
        }
        (parse.items, intact)
    }

    /// The bytes of a file: held when they are at most `cap`, else read as
    /// they go.
    fn file<'a>(&'a mut self, v: &'a mut Vol<'_>, item: &Item, cap: u64) -> Got<'a> {
        let size = u64::from(item.size);
        if size == 0 {
            return Got::Whole(Vec::new());
        }
        let want = size.div_ceil(self.cluster);
        let chain = Chain {
            fat: self,
            next: Some(item.first),
            want,
            got: 0,
            broken: false,
        };
        read_file(v, Pieces::new(chain, size), size, cap)
    }
}

/// The runs of clusters of a file's chain, found as they are read.
struct Chain<'a> {
    fat: &'a mut Fat,
    /// Where the next run starts, if the chain goes on.
    next: Option<u32>,
    /// The clusters of the file not yet in a run.
    want: u64,
    /// The clusters followed so far.
    got: u64,
    /// The chain breaks, loops or ends before the file does.
    broken: bool,
}

impl Plan for Chain<'_> {
    fn next(&mut self, v: &mut Vol) -> Next {
        if self.want == 0 {
            return Next::End;
        }
        let Some(first) = self.next.filter(|_| !self.broken) else {
            return Next::Broken;
        };
        let mut c = first;
        let mut n = 0u64;
        loop {
            // A chain longer than the volume has clusters comes back on itself.
            if self.got >= u64::from(self.fat.clusters) {
                self.broken = true;
                break;
            }
            n = n.saturating_add(1);
            self.got = self.got.saturating_add(1);
            self.want = self.want.saturating_sub(1);
            if self.want == 0 {
                break;
            }
            match self.fat.link(v, c) {
                Link::Next(next) if u64::from(next) == u64::from(c).saturating_add(1) => c = next,
                Link::Next(next) => {
                    self.next = Some(next);
                    break;
                }
                Link::End | Link::Broken => {
                    self.broken = true;
                    break;
                }
            }
        }
        match self.fat.at(first) {
            Some(at) if n > 0 => Next::Piece(Piece::Disk(at, n.saturating_mul(self.fat.cluster))),
            _ => Next::Broken,
        }
    }
}

/// Reads directory entries, across the clusters of a directory.
#[derive(Default)]
struct Parser {
    items: Vec<Item>,
    /// The long name being put together: its parts by position (1 from the
    /// end), the checksum they carry and the count they say they are.
    parts: Vec<Option<[u16; 13]>>,
    sum: u8,
}

impl Parser {
    /// Read the entries of `block`. True where the directory ends in it, or
    /// holds as many as `limit`.
    fn feed(&mut self, block: &[u8], wide: bool, limit: usize) -> bool {
        for e in block.as_chunks::<32>().0 {
            if e[0] == 0 {
                return true;
            }
            if self.items.len() >= limit {
                return true;
            }
            if e[0] == 0xE5 {
                self.parts.clear();
                continue;
            }
            let attr = e[11];
            if attr & 0x3F == ATTR_LONG {
                self.part(e);
                continue;
            }
            if attr & ATTR_VOLUME != 0 {
                self.parts.clear();
                continue;
            }
            let name = self.name(e);
            self.parts.clear();
            if name == "." || name == ".." {
                continue;
            }
            let hi = if wide { u32::from(le16(e, 20)) } else { 0 };
            self.items.push(Item {
                name,
                dir: attr & ATTR_DIR != 0,
                first: u32::from(le16(e, 26)) | hi.saturating_mul(1 << 16),
                size: le32(e, 28),
                mtime: dos_time(le16(e, 24), le16(e, 22)),
            });
        }
        false
    }

    /// Take in an entry that is a part of a long name.
    fn part(&mut self, e: &[u8]) {
        let seq = usize::from(e[0] & 0x3F);
        let mut chars = [0u16; 13];
        for (i, c) in chars.iter_mut().enumerate() {
            let at = match i {
                0..=4 => 1usize.saturating_add(i.saturating_mul(2)),
                5..=10 => 14usize.saturating_add(i.saturating_sub(5).saturating_mul(2)),
                _ => 28usize.saturating_add(i.saturating_sub(11).saturating_mul(2)),
            };
            *c = le16(e, at);
        }
        // The first part met is the last of the name, marked, and 20 is the most.
        if e[0] & 0x40 != 0 {
            self.parts.clear();
            if seq == 0 || seq > 20 {
                return;
            }
            self.parts.resize(seq, None);
            self.sum = e[13];
        } else if self.parts.is_empty() || e[13] != self.sum {
            self.parts.clear();
            return;
        }
        match seq.checked_sub(1).and_then(|i| self.parts.get_mut(i)) {
            Some(slot) => *slot = Some(chars),
            None => self.parts.clear(),
        }
    }

    /// The name of the short entry `e`: its long name where there is one that
    /// is whole and is its own, else its short name.
    fn name(&self, e: &[u8]) -> String {
        if !self.parts.is_empty()
            && self.parts.iter().all(Option::is_some)
            && self.sum == short_sum(e)
        {
            let units: Vec<u16> = self
                .parts
                .iter()
                .flatten()
                .flatten()
                .copied()
                .take_while(|&u| u != 0)
                .collect();
            return String::from_utf16_lossy(&units);
        }
        short_name(e)
    }
}

/// The checksum a long name carries of its short name.
fn short_sum(e: &[u8]) -> u8 {
    e.iter().take(11).fold(0u8, |sum, &c| {
        (sum >> 1).wrapping_add((sum & 1) << 7).wrapping_add(c)
    })
}

/// The 8.3 name of a directory entry.
fn short_name(e: &[u8]) -> String {
    // The case flags NT keeps of the base and of the extension.
    let (lower_base, lower_ext) = (e[12] & 0x08 != 0, e[12] & 0x10 != 0);
    let text = |b: &[u8], lower: bool| -> String {
        let end = b
            .iter()
            .rposition(|&c| c != b' ')
            .map_or(0, |i| i.saturating_add(1));
        b.iter()
            .take(end)
            .map(|&c| match c {
                0x80..=0xFF => CP437
                    .chars()
                    .nth(usize::from(c).saturating_sub(0x80))
                    .unwrap_or('?'),
                _ if lower => char::from(c).to_ascii_lowercase(),
                _ => char::from(c),
            })
            .collect()
    };
    let mut base = e[..8].to_vec();
    // A first byte of 0xE5 is stored as 0x05, 0xE5 marking a deleted entry.
    if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let (base, ext) = (text(&base, lower_base), text(&e[8..11], lower_ext));
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// A DOS date and time, local with no zone.
fn dos_time(date: u16, time: u16) -> Option<Mtime> {
    let (day, month) = (date & 0x1F, (date >> 5) & 0x0F);
    let (hour, minute, second) = (
        time >> 11,
        (time >> 5) & 0x3F,
        (time & 0x1F).saturating_mul(2),
    );
    if date == 0
        || !(1..=12).contains(&month)
        || day == 0
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(Mtime::Local {
        year: 1980u16.saturating_add(date >> 9),
        month: u8::try_from(month).ok()?,
        day: u8::try_from(day).ok()?,
        hour: u8::try_from(hour).ok()?,
        minute: u8::try_from(minute).ok()?,
        second: u8::try_from(second).ok()?,
    })
}

/// The volume's boot sector, or `None` where it describes none a system would
/// mount.
fn open(v: &mut Vol) -> Option<(Fat, Dir)> {
    let b = v.at(0, 512)?;
    let sector = u64::from(le16(&b, 11));
    let spc = u64::from(b[13]);
    if !matches!(sector, 512 | 1024 | 2048 | 4096) || spc == 0 || !spc.is_power_of_two() {
        return None;
    }
    let reserved = u64::from(le16(&b, 14));
    let fats = u64::from(b[16]);
    let root_entries = u64::from(le16(&b, 17));
    let total = match le16(&b, 19) {
        0 => u64::from(le32(&b, 32)),
        n => u64::from(n),
    };
    let wide = le16(&b, 22) == 0;
    let per_fat = if wide {
        u64::from(le32(&b, 36))
    } else {
        u64::from(le16(&b, 22))
    };
    if reserved == 0 || fats == 0 || per_fat == 0 {
        return None;
    }
    // The root directory of FAT12/16 is a run of sectors, 32 bytes an entry.
    let root_sectors = root_entries.saturating_mul(32).div_ceil(sector);
    let first_data = reserved
        .saturating_add(fats.saturating_mul(per_fat))
        .saturating_add(root_sectors);
    // Nothing is read from past the volume.
    let total = total.min(v.len.checked_div(sector)?);
    let clusters = total
        .checked_sub(first_data)?
        .checked_div(spc)
        .filter(|&n| n > 0)?;
    // The number of clusters, not the label, says which FAT it is.
    let bits = if wide {
        32
    } else if clusters < 4085 {
        12
    } else {
        16
    };
    // FAT32 can keep one copy of the table in use and not mirror it.
    let active = if wide && le16(&b, 40) & 0x80 != 0 {
        u64::from(le16(&b, 40) & 0x0F).min(fats.saturating_sub(1))
    } else {
        0
    };
    // The table holds an entry for every cluster, and two more.
    let room = per_fat
        .saturating_mul(sector)
        .saturating_mul(8)
        .checked_div(u64::from(bits))?
        .saturating_sub(2);
    let clusters = u32::try_from(clusters.min(room).min(0x0FFF_FFF5)).ok()?;
    if clusters == 0 {
        return None;
    }
    let table = reserved
        .saturating_add(active.saturating_mul(per_fat))
        .saturating_mul(sector);
    let fat = Fat {
        cluster: sector.saturating_mul(spc),
        bits,
        clusters,
        table,
        root: reserved
            .saturating_add(fats.saturating_mul(per_fat))
            .saturating_mul(sector),
        root_len: root_sectors.saturating_mul(sector),
        data: first_data.saturating_mul(sector),
        root_cluster: le32(&b, 44),
        pages: HashMap::new(),
    };
    let root = if wide {
        Dir::Chain(fat.root_cluster)
    } else {
        Dir::Root
    };
    Some((fat, root))
}

/// Walk a FAT volume given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the FAT volume `disk`, which is `len` bytes long, handing each file to
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
    match v.at(0, 512) {
        Some(boot) if is_fat(&boot) => {}
        _ => return Ok(None),
    }
    let Some((mut fat, root)) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "FAT open: the boot sector or the tables are unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    let mut left = u64::from(fat.clusters);
    let mut damaged = false;
    // A directory is walked once, however many entries name it.
    let mut seen: HashSet<u32> = HashSet::new();
    if let Dir::Chain(first) = root {
        seen.insert(first);
    }
    let mut stack = vec![(root, String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        let (items, intact) = fat.items(&mut v, dir, &mut left, limit);
        damaged |= !intact;
        let mut below = Vec::new();
        for item in items {
            budget.count_entry()?;
            let path = if prefix.is_empty() {
                item.name.clone()
            } else {
                format!("{prefix}/{}", item.name)
            };
            if item.dir {
                if item.first < 2 || depth >= MAX_DEPTH {
                    damaged = true;
                } else if seen.insert(item.first) {
                    below.push((Dir::Chain(item.first), path, depth.saturating_add(1)));
                }
                continue;
            }
            let attrs = Attrs {
                mode: None,
                mtime: item.mtime,
            };
            if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                fat.file(&mut v, &item, cap)
            })? {
                return Ok(Some(r));
            }
        }
        stack.extend(below.into_iter().rev());
    }
    if damaged {
        return Err(LimitHit::corrupt(
            "FAT walk: the volume is damaged; the files before the damage were scanned".into(),
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

    /// A directory entry.
    fn entry(name: &[u8; 11], attr: u8, nt: u8, first: u16, size: u32) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[..11].copy_from_slice(name);
        e[11] = attr;
        e[12] = nt;
        e[26..28].copy_from_slice(&first.to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// The entries of a long name for the short entry with the name `short`,
    /// last part first, as they are in a directory.
    fn parts(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        if !units.len().is_multiple_of(13) {
            units.push(0);
        }
        while !units.len().is_multiple_of(13) {
            units.push(0xFFFF);
        }
        let sum = short_sum(short);
        let n = units.len() / 13;
        let mut out = Vec::new();
        for (i, chunk) in units.chunks(13).enumerate().rev() {
            let mut e = [0u8; 32];
            e[0] = (i + 1) as u8 | if i + 1 == n { 0x40 } else { 0 };
            e[11] = 0x0F;
            e[13] = sum;
            for (k, u) in chunk.iter().enumerate() {
                let at = match k {
                    0..=4 => 1 + 2 * k,
                    5..=10 => 14 + 2 * (k - 5),
                    _ => 28 + 2 * (k - 11),
                };
                e[at..at + 2].copy_from_slice(&u.to_le_bytes());
            }
            out.push(e);
        }
        out
    }

    fn names(block: &[[u8; 32]]) -> Vec<String> {
        let mut p = Parser::default();
        p.feed(&block.concat(), false, 100);
        p.items.into_iter().map(|i| i.name).collect()
    }

    #[test]
    fn a_short_name_has_its_case_flags_and_its_code_page() {
        let n = |name: &[u8; 11], nt: u8| short_name(&entry(name, 0x20, nt, 2, 0));
        assert_eq!(n(b"README  TXT", 0), "README.TXT");
        assert_eq!(n(b"README  TXT", 0x18), "readme.txt");
        assert_eq!(n(b"README  TXT", 0x08), "readme.TXT");
        assert_eq!(n(b"README  TXT", 0x10), "README.txt");
        assert_eq!(n(b"MAKEFILE   ", 0x08), "makefile");
        // A name that begins with 0xE5 is stored with 0x05.
        assert_eq!(n(b"\x05AB     DAT", 0), "\u{3c3}AB.DAT");
        // Bytes from 0x80 are CP437.
        assert_eq!(n(b"\x80\x81\xB0     TXT", 0), "\u{c7}\u{fc}\u{2591}.TXT");
    }

    #[test]
    fn a_long_name_is_taken_when_it_is_whole_and_its_checksum_is_the_short_names() {
        let short = *b"LONGNA~1TXT";
        let e = entry(&short, 0x20, 0, 2, 1);
        let long = "a long name.text";
        let mut block = parts(long, &short);
        block.push(e);
        assert_eq!(names(&block), [long]);

        // A name of exactly 13 characters has no end marker.
        let mut block = parts("thirteen.char", &short);
        block.push(e);
        assert_eq!(names(&block), ["thirteen.char"]);

        // The checksum of another short name.
        let mut other = parts(long, b"OTHER   TXT");
        other.push(e);
        assert_eq!(names(&other), ["LONGNA~1.TXT"]);

        // A part missing.
        let mut cut = parts("a name that takes three parts of thirteen", &short);
        cut.remove(1);
        cut.push(e);
        assert_eq!(names(&cut), ["LONGNA~1.TXT"]);

        // Parts that begin with no last part are not a name.
        let mut orphan = parts("a name that takes two parts", &short);
        orphan.remove(0);
        orphan.push(e);
        assert_eq!(names(&orphan), ["LONGNA~1.TXT"]);

        // A deleted entry between the parts and the short entry ends the name.
        let mut gone = parts(long, &short);
        gone.push(entry(b"\xE5ELETED TXT", 0x20, 0, 9, 1));
        gone.push(e);
        assert_eq!(names(&gone), ["LONGNA~1.TXT"]);

        // The name of a short entry is not carried to the next.
        let mut two = parts(long, &short);
        two.push(e);
        two.push(entry(b"NEXT    TXT", 0x20, 0, 3, 1));
        assert_eq!(names(&two), [long, "NEXT.TXT"]);
    }

    #[test]
    fn a_long_name_is_unicode() {
        let short = *b"CAF~1   TXT";
        let mut block = parts("caf\u{e9} \u{65e5}\u{672c} \u{1f600}.txt", &short);
        block.push(entry(&short, 0x20, 0, 2, 1));
        assert_eq!(names(&block), ["caf\u{e9} \u{65e5}\u{672c} \u{1f600}.txt"]);
    }

    #[test]
    fn a_directory_is_read_to_its_end_marker() {
        let block = [
            entry(b"VOLUME     ", 0x08, 0, 0, 0),
            entry(b".          ", 0x10, 0, 2, 0),
            entry(b"..         ", 0x10, 0, 0, 0),
            entry(b"A       TXT", 0x20, 0, 3, 5),
            entry(b"\xE5DELETE TXT", 0x20, 0, 4, 5),
            entry(b"SUB        ", 0x10, 0, 5, 0),
            [0u8; 32],
            entry(b"AFTER   TXT", 0x20, 0, 6, 5),
        ];
        let mut p = Parser::default();
        assert!(p.feed(&block.concat(), false, 100));
        let got: Vec<_> = p.items.iter().map(|i| (i.name.as_str(), i.dir)).collect();
        assert_eq!(got, [("A.TXT", false), ("SUB", true)]);
        // The first cluster of FAT32 has its high half in another field.
        let mut e = entry(b"BIG     BIN", 0x20, 0, 0x1234, 1);
        e[20..22].copy_from_slice(&0x0005u16.to_le_bytes());
        for (wide, first) in [(false, 0x1234), (true, 0x5_1234)] {
            let mut p = Parser::default();
            p.feed(&e, wide, 100);
            assert_eq!(p.items[0].first, first);
        }
    }

    #[test]
    fn a_time_is_a_wall_clock_one_or_none() {
        // 2024-03-05 14:30:12.
        let date = ((2024 - 1980) << 9) | (3 << 5) | 5;
        let time = (14 << 11) | (30 << 5) | 6;
        assert_eq!(
            dos_time(date, time),
            Some(Mtime::Local {
                year: 2024,
                month: 3,
                day: 5,
                hour: 14,
                minute: 30,
                second: 12
            })
        );
        assert_eq!(dos_time(0, time), None);
        assert_eq!(dos_time((2024 - 1980) << 9 | (13 << 5) | 5, time), None);
        assert_eq!(dos_time(date & !0x1F, time), None);
        assert_eq!(dos_time(date, 25 << 11), None);
    }

    /// A volume of 512-byte sectors, one to a cluster, with the table of `bits`
    /// and the clusters numbered from 2.
    fn volume(bits: u32, fat: &[u16]) -> (Fat, Vec<u8>) {
        let mut d = vec![0u8; 4096];
        for (c, &v) in fat.iter().enumerate() {
            if bits == 16 {
                d[c * 2..c * 2 + 2].copy_from_slice(&v.to_le_bytes());
            } else {
                let at = c + c / 2;
                let pair = u16::from_le_bytes([d[at], d[at + 1]]);
                let pair = if c % 2 == 1 {
                    (pair & 0xF) | (v << 4)
                } else {
                    (pair & 0xF000) | v
                };
                d[at..at + 2].copy_from_slice(&pair.to_le_bytes());
            }
        }
        let f = Fat {
            cluster: 512,
            bits,
            clusters: 100,
            table: 0,
            root: 0,
            root_len: 0,
            data: 0,
            root_cluster: 0,
            pages: HashMap::new(),
        };
        (f, d)
    }

    fn link(f: &mut Fat, d: Vec<u8>, c: u32) -> String {
        let mut cur = Cursor::new(d);
        let mut v = Vol {
            disk: &mut cur,
            len: 4096,
            max: 1 << 20,
        };
        match f.link(&mut v, c) {
            Link::Next(n) => format!("next {n}"),
            Link::End => "end".into(),
            Link::Broken => "broken".into(),
        }
    }

    #[test]
    fn the_entries_of_a_table_are_followed_in_each_width() {
        // 12 bits: two entries in three bytes.
        let t12 = [0xFF8, 0xFFF, 3, 0x05B, 0xFF8, 0xFFF, 0, 1, 200];
        for (c, want) in [
            (2, "next 3"),
            (3, "next 91"),
            (4, "end"),
            (5, "end"),
            // Free, not a chain.
            (6, "broken"),
            // Cluster 1 is none, and 200 is past the clusters there are.
            (7, "broken"),
            (8, "broken"),
            (1, "broken"),
            (101, "broken"),
        ] {
            let (mut f, d) = volume(12, &t12);
            assert_eq!(link(&mut f, d, c), want, "FAT12 cluster {c}");
        }
        let t16 = [0xFFF8, 0xFFFF, 3, 0xFFFF, 0, 0xFFF7, 0xFFF8];
        for (c, want) in [
            (2, "next 3"),
            (3, "end"),
            (4, "broken"),
            (5, "broken"),
            (6, "end"),
        ] {
            let (mut f, d) = volume(16, &t16);
            assert_eq!(link(&mut f, d, c), want, "FAT16 cluster {c}");
        }
        // 32 bits keep 28 of them.
        let mut d = vec![0u8; 4096];
        d[8..12].copy_from_slice(&0xF000_0003u32.to_le_bytes());
        d[12..16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        let (mut f, _) = volume(32, &[]);
        assert_eq!(link(&mut f, d.clone(), 2), "next 3");
        assert_eq!(link(&mut f, d, 3), "end");
    }

    /// A boot sector of a FAT16 volume of 4200 sectors.
    fn boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[3..11].copy_from_slice(b"MSDOS5.0");
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&1u16.to_le_bytes());
        b[16] = 2;
        b[17..19].copy_from_slice(&512u16.to_le_bytes());
        b[19..21].copy_from_slice(&4200u16.to_le_bytes());
        b[22..24].copy_from_slice(&17u16.to_le_bytes());
        b[54..62].copy_from_slice(b"FAT16   ");
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        b
    }

    fn opened(boot: &[u8]) -> Option<(u32, u32)> {
        let mut d = vec![0u8; 4200 * 512];
        d[..512].copy_from_slice(boot);
        let len = d.len() as u64;
        let mut cur = Cursor::new(d);
        let mut v = Vol {
            disk: &mut cur,
            len,
            max: 1 << 20,
        };
        open(&mut v).map(|(f, _)| (f.bits, f.clusters))
    }

    #[test]
    fn the_number_of_clusters_says_which_fat_it_is() {
        // 4200 sectors less one reserved, 2 tables of 17 and 32 of root.
        assert_eq!(opened(&boot()), Some((16, 4133)));
        let mut small = boot();
        small[13] = 2;
        assert_eq!(opened(&small), Some((12, 2066)));
        // The table of a FAT32 volume is in another field.
        let mut wide = boot();
        wide[17..19].fill(0);
        wide[22..24].fill(0);
        wide[36..40].copy_from_slice(&17u32.to_le_bytes());
        wide[44..48].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(opened(&wide).map(|x| x.0), Some(32));
    }

    #[test]
    fn a_fat32_volume_that_does_not_mirror_its_tables_is_read_through_the_one_in_use() {
        let table = |ext_flags: u16| {
            let mut b = boot();
            b[17..19].fill(0);
            b[22..24].fill(0);
            b[36..40].copy_from_slice(&17u32.to_le_bytes());
            b[40..42].copy_from_slice(&ext_flags.to_le_bytes());
            b[44..48].copy_from_slice(&2u32.to_le_bytes());
            let mut d = vec![0u8; 4200 * 512];
            d[..512].copy_from_slice(&b);
            let len = d.len() as u64;
            let mut cur = Cursor::new(d);
            let mut v = Vol {
                disk: &mut cur,
                len,
                max: 1 << 20,
            };
            open(&mut v).map(|(f, _)| f.table)
        };
        // Mirrored: the first. Not mirrored, the second in use: the second.
        assert_eq!(table(0), Some(512));
        assert_eq!(table(0x80), Some(512));
        assert_eq!(table(0x81), Some(512 + 17 * 512));
        // One that is not there is the last there is.
        assert_eq!(table(0x85), Some(512 + 17 * 512));
    }

    #[test]
    fn a_boot_sector_that_describes_no_volume_is_not_opened() {
        // What is written, and where.
        let edits: [(&str, usize, &[u8]); 8] = [
            ("sector size", 11, &500u16.to_le_bytes()),
            ("cluster size 0", 13, &[0]),
            ("cluster size 3", 13, &[3]),
            ("no reserved sectors", 14, &[0, 0]),
            ("no tables", 16, &[0]),
            ("empty tables", 22, &[0, 0]),
            ("tables past the volume", 22, &5000u16.to_le_bytes()),
            ("no sectors", 19, &[0, 0]),
        ];
        for (what, at, bytes) in edits {
            let mut b = boot();
            b[at..at + bytes.len()].copy_from_slice(bytes);
            assert_eq!(opened(&b), None, "{what}");
        }
    }

    /// A FAT16 volume holding `files` in its root, each in clusters in order.
    fn image(files: &[(&[u8; 11], &[u8])]) -> Vec<u8> {
        let mut d = vec![0u8; 4200 * 512];
        d[..512].copy_from_slice(&boot());
        // The first table at 512, the root at 35 * 512, cluster 2 at 67 * 512.
        let (fat, root, data) = (512, 35 * 512, 67 * 512);
        d[fat..fat + 4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
        let mut next = 2usize;
        for (i, (name, bytes)) in files.iter().enumerate() {
            let n = bytes.len().div_ceil(512).max(1);
            for c in next..next + n {
                let v: u16 = if c + 1 == next + n {
                    0xFFFF
                } else {
                    c as u16 + 1
                };
                d[fat + c * 2..fat + c * 2 + 2].copy_from_slice(&v.to_le_bytes());
            }
            let at = data + (next - 2) * 512;
            d[at..at + bytes.len()].copy_from_slice(bytes);
            let e = entry(name, 0x20, 0, next as u16, bytes.len() as u32);
            d[root + i * 32..root + i * 32 + 32].copy_from_slice(&e);
            next += n;
        }
        d
    }

    /// A member as the tests see it: its name, its length and what it reports.
    type Member = (String, usize, Option<&'static str>);

    fn walked(d: &[u8], limits: Limits) -> (Vec<Member>, Result<(), LimitHit>) {
        let mut out = Vec::new();
        let mut budget = Budget::new(limits);
        let len = d.len() as u64;
        let end = walk_volume(Cursor::new(d), len, &mut budget, &mut |e, _| {
            let e = e.whole();
            out.push((e.name, e.data.len(), e.unsupported));
            None::<()>
        });
        (out, end.map(|_| ()))
    }

    #[test]
    fn the_files_of_a_root_come_out_with_what_their_chains_hold() {
        let big = vec![7u8; 1300];
        let d = image(&[(b"A       TXT", b"hello"), (b"BIG     BIN", &big)]);
        let (e, end) = walked(&d, Limits::default());
        end.unwrap();
        assert_eq!(
            e,
            [
                ("A.TXT".to_string(), 5, None),
                ("BIG.BIN".to_string(), 1300, None)
            ]
        );
    }

    #[test]
    fn a_chain_that_runs_in_a_circle_is_read_as_far_as_the_size_asks_and_no_further() {
        let mut d = image(&[(b"LOOP    BIN", &vec![1u8; 1024])]);
        // Make the file 5 clusters long by its size: cluster 3 leads back to 2.
        let root = 35 * 512;
        d[root + 28..root + 32].copy_from_slice(&2560u32.to_le_bytes());
        d[512 + 6..512 + 8].copy_from_slice(&2u16.to_le_bytes());
        let (e, end) = walked(&d, Limits::default());
        end.unwrap();
        assert_eq!(e, [("LOOP.BIN".to_string(), 2560, None)]);
    }

    #[test]
    fn a_chain_that_ends_or_breaks_early_is_a_file_cut_short() {
        // Cluster 2 ends the chain, or leads to cluster 1, which is none.
        for next in [0xFFFFu16, 0xFFF7, 1] {
            let mut d = image(&[(b"CUT     BIN", &vec![1u8; 1024])]);
            d[512 + 4..512 + 6].copy_from_slice(&next.to_le_bytes());
            let (e, end) = walked(&d, Limits::default());
            end.unwrap();
            assert_eq!(
                e,
                [(
                    "CUT.BIN".to_string(),
                    512,
                    Some("file could not be read from the volume")
                )],
                "{next:#x}"
            );
        }
    }

    #[test]
    fn the_entry_past_the_member_limit_is_counted_and_stops_the_walk() {
        let d = image(&[
            (b"A       TXT", b"a"),
            (b"B       TXT", b"b"),
            (b"C       TXT", b"c"),
        ]);
        let run = |max: u64| {
            let limits = Limits {
                max_members: max,
                ..Limits::default()
            };
            walked(&d, limits)
        };
        let (e, end) = run(3);
        end.unwrap();
        assert_eq!(e.len(), 3);
        let (e, end) = run(2);
        assert!(!end.unwrap_err().is_corrupt());
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn a_file_over_the_buffer_limit_is_read_as_it_goes_and_the_walk_goes_on() {
        let d = image(&[(b"BIG     BIN", &vec![1u8; 4000]), (b"SMALL   TXT", b"x")]);
        let limits = Limits {
            max_buffer_bytes: 1000,
            ..Limits::default()
        };
        let mut budget = Budget::new(limits);
        let len = d.len() as u64;
        let (e, end) = collected(|emit| walk_volume(Cursor::new(&d[..]), len, &mut budget, emit));
        end.unwrap();
        assert_eq!(e[0].0.name, "BIG.BIN");
        assert_eq!(e[0].0.data, vec![1u8; 4000]);
        assert!(e[0].1, "a file past the limit is not held");
        assert_eq!(e[0].0.unsupported, None);
        assert_eq!((e[1].0.name.as_str(), e[1].1), ("SMALL.TXT", false));
    }
}
