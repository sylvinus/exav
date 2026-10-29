//! exFAT: the files of a volume, read where they lie.
//!
//! The filesystem of the memory cards and USB sticks bigger than FAT32 holds.
//! The volume is a `Read + Seek`, read where the walk goes: the boot sector,
//! the part of the allocation table a chain passes through, each directory's
//! clusters and each file's runs of clusters. Only a file is ever held, bounded
//! by the buffer limit.
//!
//! ```text
//! boot sector          sector and cluster sizes, where the table and the
//!                      cluster heap start, the first cluster of the root
//!   allocation table   one entry per cluster: the next of its chain, or the end
//!   cluster heap       directories: sets of 32-byte entries, a file being a
//!                      file entry, a stream entry (first cluster, size, and
//!                      whether the clusters are in a row) and name entries
//! ```
//!
//! A file whose stream says its clusters are in a row has no chain in the table.
//! The bytes of a file past its valid length read as zeros, as they do to the
//! system that mounts the volume. The checksums of the boot region and of the
//! entry sets, and the hash of a name, are not checked, nor is the bitmap of
//! the clusters in use read: a file is where its entry says.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};

use super::vol::{
    Attrs, Emit, Fill, Got, Next, Piece, Pieces, Plan, Step, Vol, give, le16, le32, le64, read_file,
};
use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, LimitHit, Mtime};

/// The most directories a path passes through.
const MAX_DEPTH: usize = 256;

/// Bytes of the allocation table kept at a time, and how many of those.
const PAGE: u64 = 4096;
const PAGES: usize = 64;

/// File attribute bit of a folder.
const ATTR_DIR: u16 = 0x10;

/// Whether `data`, the start of a volume, holds the boot sector of an exFAT
/// volume: its name, the zeroes where a FAT volume has its parameters, and the
/// signature that ends a boot sector.
pub(crate) fn is_exfat(data: &[u8]) -> bool {
    data.len() >= 512
        && data.get(3..11) == Some(b"EXFAT   ".as_slice())
        && data.get(510..512) == Some(&[0x55, 0xAA][..])
        && data.get(11..64).is_some_and(|z| z.iter().all(|&b| b == 0))
}

/// What the boot sector says of the volume.
struct Exfat {
    /// Bytes in a cluster.
    cluster: u64,
    /// Clusters of data, numbered from 2.
    clusters: u32,
    /// Byte offsets of the table in use and of cluster 2.
    table: u64,
    heap: u64,
    root: u32,
    pages: HashMap<u64, Vec<u8>>,
}

/// Where the bytes of a file or a folder are.
#[derive(Clone, Copy)]
struct Place {
    first: u32,
    /// The clusters are one after the other, with no chain in the table.
    in_a_row: bool,
    /// The size the entry gives, which is not known of the root.
    size: Option<u64>,
}

/// A file or a folder in a folder.
struct Item {
    name: String,
    dir: bool,
    place: Place,
    /// How much of the file is written: the rest reads as zeros.
    valid: u64,
    mtime: Option<Mtime>,
}

impl Exfat {
    fn table_byte(&mut self, v: &mut Vol, off: u64) -> Option<u8> {
        let (page, at) = (off.checked_div(PAGE)?, off.checked_rem(PAGE)?);
        if !self.pages.contains_key(&page) {
            let start = self.table.checked_add(page.checked_mul(PAGE)?)?;
            let want = crate::bytes::to_usize(PAGE.min(v.len.checked_sub(start)?));
            let got = v.at(start, want)?;
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

    /// The cluster after `c` in its chain: `Some(None)` at the end of it, and
    /// `None` where the table does not say.
    fn next(&mut self, v: &mut Vol, c: u32) -> Option<Option<u32>> {
        if c < 2 || c > self.clusters.saturating_add(1) {
            return None;
        }
        let off = u64::from(c).checked_mul(4)?;
        let mut raw = 0u32;
        for i in (0..4u64).rev() {
            let b = self.table_byte(v, off.checked_add(i)?)?;
            raw = raw.checked_mul(256)?.checked_add(u32::from(b))?;
        }
        match raw {
            0xFFFF_FFF8.. => Some(None),
            2.. if raw <= self.clusters.saturating_add(1) => Some(Some(raw)),
            _ => None,
        }
    }

    /// The byte offset of cluster `c`.
    fn at(&self, c: u32) -> Option<u64> {
        u64::from(c.checked_sub(2)?)
            .checked_mul(self.cluster)?
            .checked_add(self.heap)
    }

    /// The runs of the clusters of `place`, as (first cluster, clusters), up
    /// to `want` of them (all of them where it is not given). The flag is false
    /// where the chain breaks, loops or ends before that.
    fn runs(&mut self, v: &mut Vol, place: Place, want: Option<u64>) -> (Vec<(u32, u64)>, bool) {
        if place.in_a_row {
            let n = want.unwrap_or(0);
            let last = u64::from(place.first).saturating_add(n).saturating_sub(1);
            let fits = place.first >= 2 && last <= u64::from(self.clusters).saturating_add(1);
            return (vec![(place.first, n)], fits);
        }
        let mut runs: Vec<(u32, u64)> = Vec::new();
        let mut c = place.first;
        let mut got = 0u64;
        loop {
            // A chain longer than the volume has clusters comes back on itself.
            if got >= u64::from(self.clusters) || want.is_some_and(|w| got >= w) {
                return (runs, want.is_some());
            }
            match runs.last_mut() {
                Some((start, n)) if u64::from(*start).saturating_add(*n) == u64::from(c) => {
                    *n = n.saturating_add(1);
                }
                _ => runs.push((c, 1)),
            }
            got = got.saturating_add(1);
            match self.next(v, c) {
                Some(Some(next)) => c = next,
                Some(None) if want.is_none() => return (runs, true),
                _ => return (runs, want.is_some_and(|w| got >= w)),
            }
        }
    }

    /// The items of the folder at `place`, up to `limit` of them. `left`
    /// counts the clusters of folders the walk may still read. The flag is
    /// false where the folder is damaged.
    fn items(
        &mut self,
        v: &mut Vol,
        place: Place,
        left: &mut u64,
        limit: usize,
    ) -> (Vec<Item>, bool) {
        let want = place.size.map(|s| s.div_ceil(self.cluster));
        let (runs, mut intact) = self.runs(v, place, want);
        let mut parse = Parser::default();
        'runs: for (first, n) in runs {
            for i in 0..n {
                if *left == 0 {
                    intact = false;
                    break 'runs;
                }
                *left = left.saturating_sub(1);
                let c = u32::try_from(u64::from(first).saturating_add(i)).unwrap_or(0);
                let block = self
                    .at(c)
                    .and_then(|o| v.at(o, crate::bytes::to_usize(self.cluster)));
                let Some(block) = block else {
                    intact = false;
                    break 'runs;
                };
                if parse.feed(&block, limit) {
                    break 'runs;
                }
            }
        }
        (parse.items, intact)
    }

    /// The bytes of a file: held when they are at most `cap`, else read as
    /// they go.
    fn file<'a>(&'a mut self, v: &'a mut Vol<'_>, item: &Item, cap: u64) -> Got<'a> {
        let Some(size) = item.place.size else {
            return Got::Why("exFAT file without a size");
        };
        if size == 0 {
            return Got::Whole(Vec::new());
        }
        let want = size.div_ceil(self.cluster);
        let chain = Chain {
            fat: self,
            next: Some(item.place.first),
            row: item.place.in_a_row,
            want,
            got: 0,
            broken: false,
        };
        let fill = Valid {
            inner: Pieces::new(chain, size),
            at: 0,
            valid: item.valid.min(size),
        };
        read_file(v, fill, size, cap)
    }
}

/// The runs of clusters of a file, found as they are read.
struct Chain<'a> {
    fat: &'a mut Exfat,
    /// Where the next run starts, if the chain goes on.
    next: Option<u32>,
    /// The clusters are one after the other, with no chain in the table.
    row: bool,
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
        if self.row {
            let n = self.want;
            self.want = 0;
            let last = u64::from(first).saturating_add(n).saturating_sub(1);
            if first < 2 || last > u64::from(self.fat.clusters).saturating_add(1) {
                return Next::Broken;
            }
            return match self.fat.at(first) {
                Some(at) => Next::Piece(Piece::Disk(at, n.saturating_mul(self.fat.cluster))),
                None => Next::Broken,
            };
        }
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
            match self.fat.next(v, c) {
                Some(Some(next)) if u64::from(next) == u64::from(c).saturating_add(1) => c = next,
                Some(Some(next)) => {
                    self.next = Some(next);
                    break;
                }
                Some(None) | None => {
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

/// A file's bytes with what is past its valid length read as zeros: it was
/// never written.
struct Valid<F> {
    inner: F,
    /// How many bytes of the file `inner` has given.
    at: u64,
    valid: u64,
}

impl<F: Fill> Fill for Valid<F> {
    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        let from = out.len();
        let step = self.inner.fill(v, out);
        let got = out.len().saturating_sub(from) as u64;
        // The first byte of what was given that is past the valid length.
        let zero = crate::bytes::to_usize(self.valid.saturating_sub(self.at).min(got));
        if let Some(tail) = out.get_mut(from.saturating_add(zero)..) {
            tail.fill(0);
        }
        self.at = self.at.saturating_add(got);
        step
    }
}

/// Reads the entries of a directory, across its clusters.
#[derive(Default)]
struct Parser {
    items: Vec<Item>,
    /// The entry set being read: its entries so far, and how many more.
    set: Vec<[u8; 32]>,
    more: usize,
}

impl Parser {
    /// Read the entries of `block`. True where the directory ends in it, or
    /// holds as many as `limit`.
    fn feed(&mut self, block: &[u8], limit: usize) -> bool {
        for e in block.as_chunks::<32>().0 {
            if e[0] == 0 {
                return true;
            }
            if self.items.len() >= limit {
                return true;
            }
            match e[0] {
                // A file: the entry, then its secondary entries.
                0x85 => {
                    self.set = vec![*e];
                    self.more = usize::from(e[1]);
                }
                // A secondary entry of the set, in use: a stream, a name, or
                // another, which is counted and not read.
                0xC0..=0xFF if self.more > 0 && !self.set.is_empty() => {
                    self.set.push(*e);
                    self.more = self.more.saturating_sub(1);
                    if self.more == 0 {
                        self.finish();
                    }
                }
                // The bitmap, the table of upper case letters, the label, the
                // entries not in use: not files, and the end of a set.
                _ => {
                    self.set.clear();
                    self.more = 0;
                }
            }
        }
        false
    }

    /// The item the set read is.
    fn finish(&mut self) {
        let set = std::mem::take(&mut self.set);
        let (Some(file), Some(stream)) = (set.first(), set.get(1)) else {
            return;
        };
        if stream[0] != 0xC0 {
            return;
        }
        let units: Vec<u16> = set
            .iter()
            .skip(2)
            .filter(|e| e[0] == 0xC1)
            .flat_map(|e| e.get(2..).unwrap_or(&[]).as_chunks::<2>().0.iter())
            .map(|c| u16::from_le_bytes(*c))
            .take(usize::from(stream[3]))
            .collect();
        if units.is_empty() {
            return;
        }
        let size = le64(stream, 24);
        self.items.push(Item {
            name: String::from_utf16_lossy(&units),
            dir: le16(file, 4) & ATTR_DIR != 0,
            place: Place {
                first: le32(stream, 20),
                in_a_row: stream[1] & 0x02 != 0,
                size: Some(size),
            },
            valid: le64(stream, 8),
            mtime: timestamp(le32(file, 12)),
        });
    }
}

/// A timestamp of a file entry: the year since 1980, month, day, hour, minute
/// and two seconds, packed; wall-clock, the offset from UTC being another field.
fn timestamp(t: u32) -> Option<Mtime> {
    let (day, month) = ((t >> 16) & 0x1F, (t >> 21) & 0x0F);
    let (hour, minute, second) = (
        (t >> 11) & 0x1F,
        (t >> 5) & 0x3F,
        (t & 0x1F).saturating_mul(2),
    );
    if t == 0 || !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(Mtime::Local {
        year: 1980u16.saturating_add(u16::try_from(t >> 25).ok()?),
        month: u8::try_from(month).ok()?,
        day: u8::try_from(day).ok()?,
        hour: u8::try_from(hour).ok()?,
        minute: u8::try_from(minute).ok()?,
        second: u8::try_from(second).ok()?,
    })
}

/// The volume's boot sector, or `None` where it describes none a system would
/// mount.
fn open(v: &mut Vol) -> Option<Exfat> {
    let b = v.at(0, 512)?;
    if !is_exfat(&b) || le16(&b, 104) >> 8 != 1 {
        return None;
    }
    let (sector_shift, cluster_shift) = (u32::from(b[108]), u32::from(b[109]));
    if !(9..=12).contains(&sector_shift) || sector_shift.saturating_add(cluster_shift) > 25 {
        return None;
    }
    let sector = 1u64.checked_shl(sector_shift)?;
    let cluster = 1u64.checked_shl(sector_shift.saturating_add(cluster_shift))?;
    let fats = u64::from(b[110]);
    if !(1..=2).contains(&fats) {
        return None;
    }
    let (fat_at, fat_len) = (u64::from(le32(&b, 80)), u64::from(le32(&b, 84)));
    let heap = u64::from(le32(&b, 88)).checked_mul(sector)?;
    // Nothing is read from past the volume the boot sector describes.
    let volume = le64(&b, 72).saturating_mul(sector).min(v.len);
    let room = volume.checked_sub(heap)?.checked_div(cluster)?;
    let clusters = u32::try_from(u64::from(le32(&b, 92)).min(room)).ok()?;
    let root = le32(&b, 96);
    if clusters == 0 || fat_len == 0 || root < 2 || root > clusters.saturating_add(1) {
        return None;
    }
    // Two tables, and the volume flags say which is in use.
    let active = u64::from(fats == 2 && le16(&b, 106) & 1 != 0);
    let table = fat_at
        .saturating_add(active.saturating_mul(fat_len))
        .saturating_mul(sector);
    Some(Exfat {
        cluster,
        clusters,
        table,
        heap,
        root,
        pages: HashMap::new(),
    })
}

/// Walk an exFAT volume given whole as a source.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the exFAT volume `disk`, which is `len` bytes long, handing each file
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
    match v.at(0, 512) {
        Some(boot) if is_exfat(&boot) => {}
        _ => return Ok(None),
    }
    let Some(mut fs) = open(&mut v) else {
        return Err(LimitHit::corrupt(
            "exFAT open: the boot sector is unreadable".into(),
        ));
    };

    // One more than the member limit, so the entry past it is counted and the
    // walk stops there rather than ending short.
    let limit = crate::bytes::to_usize(budget.limits().max_members).saturating_add(1);
    let mut left = u64::from(fs.clusters);
    let mut damaged = false;
    // A folder is walked once, however many entries name it.
    let mut seen: HashSet<u32> = HashSet::from([fs.root]);
    let root = Place {
        first: fs.root,
        in_a_row: false,
        size: None,
    };
    let mut stack = vec![(root, String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        let (items, intact) = fs.items(&mut v, dir, &mut left, limit);
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
                if item.place.first < 2 || depth >= MAX_DEPTH {
                    damaged = true;
                } else if seen.insert(item.place.first) {
                    below.push((item.place, path, depth.saturating_add(1)));
                }
                continue;
            }
            let attrs = Attrs {
                mode: None,
                mtime: item.mtime,
            };
            if let Some(r) = give(budget, &mut *visit, path, attrs, |cap| {
                fs.file(&mut v, &item, cap)
            })? {
                return Ok(Some(r));
            }
        }
        stack.extend(below.into_iter().rev());
    }
    if damaged {
        return Err(LimitHit::corrupt(
            "exFAT walk: the volume is damaged; the files before the damage were scanned".into(),
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

    /// Sectors and clusters of 512 bytes; the table at sector 1, 4 sectors
    /// long, the heap at sector 8, 100 clusters, the root in cluster 2.
    const FAT_AT: usize = 512;
    const HEAP: usize = 8 * 512;

    struct Img(Vec<u8>);

    impl Img {
        fn new() -> Img {
            let mut d = vec![0u8; HEAP + 100 * 512];
            d[0] = 0xEB;
            d[3..11].copy_from_slice(b"EXFAT   ");
            d[72..80].copy_from_slice(&108u64.to_le_bytes());
            d[80..84].copy_from_slice(&1u32.to_le_bytes());
            d[84..88].copy_from_slice(&4u32.to_le_bytes());
            d[88..92].copy_from_slice(&8u32.to_le_bytes());
            d[92..96].copy_from_slice(&100u32.to_le_bytes());
            d[96..100].copy_from_slice(&2u32.to_le_bytes());
            d[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
            d[108] = 9;
            d[109] = 0;
            d[110] = 1;
            d[510..512].copy_from_slice(&[0x55, 0xAA]);
            let mut img = Img(d);
            img.link(2, 0xFFFF_FFFF);
            img
        }

        fn link(&mut self, c: usize, next: u32) {
            self.0[FAT_AT + c * 4..FAT_AT + c * 4 + 4].copy_from_slice(&next.to_le_bytes());
        }

        fn put(&mut self, c: usize, bytes: &[u8]) {
            let at = HEAP + (c - 2) * 512;
            self.0[at..at + bytes.len()].copy_from_slice(bytes);
        }

        /// `entries` as the directory in cluster `c`.
        fn dir(&mut self, c: usize, entries: &[Vec<[u8; 32]>]) {
            let flat: Vec<u8> = entries.iter().flatten().flatten().copied().collect();
            self.put(c, &flat);
        }
    }

    /// The entry set of a file (or folder) called `name`.
    fn set(
        name: &str,
        attr: u16,
        first: u32,
        size: u64,
        valid: u64,
        in_a_row: bool,
    ) -> Vec<[u8; 32]> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(15);
        let mut file = [0u8; 32];
        file[0] = 0x85;
        file[1] = 1 + names as u8;
        file[4..6].copy_from_slice(&attr.to_le_bytes());
        // 2024-03-05 14:30:12.
        let ts: u32 = (44 << 25) | (3 << 21) | (5 << 16) | (14 << 11) | (30 << 5) | 6;
        file[12..16].copy_from_slice(&ts.to_le_bytes());
        let mut stream = [0u8; 32];
        stream[0] = 0xC0;
        stream[1] = 0x01 | if in_a_row { 0x02 } else { 0 };
        stream[3] = units.len() as u8;
        stream[8..16].copy_from_slice(&valid.to_le_bytes());
        stream[20..24].copy_from_slice(&first.to_le_bytes());
        stream[24..32].copy_from_slice(&size.to_le_bytes());
        let mut out = vec![file, stream];
        for chunk in units.chunks(15) {
            let mut e = [0u8; 32];
            e[0] = 0xC1;
            for (i, u) in chunk.iter().enumerate() {
                e[2 + i * 2..4 + i * 2].copy_from_slice(&u.to_le_bytes());
            }
            out.push(e);
        }
        out
    }

    type Member = (String, Vec<u8>, Option<&'static str>);

    fn walked(d: &[u8], limits: Limits) -> (Vec<Member>, Result<(), LimitHit>) {
        let mut out = Vec::new();
        let mut budget = Budget::new(limits);
        let len = d.len() as u64;
        let end = walk_volume(Cursor::new(d), len, &mut budget, &mut |e, _| {
            let e = e.whole();
            out.push((e.name, e.data, e.unsupported));
            None::<()>
        });
        (out, end.map(|_| ()))
    }

    /// Files in a row, chained, written in part, empty, and long-named.
    fn mixed() -> Vec<u8> {
        let mut img = Img::new();
        // The root takes clusters 2 and 3.
        img.link(2, 3);
        img.link(3, 0xFFFF_FFFF);
        // A file in a row, in clusters 13 and 14; a file chained 15, 17;
        // another written to 600 bytes of 1000.
        img.put(13, &[b'a'; 512]);
        img.put(14, &[b'b'; 512]);
        img.put(15, &[b'c'; 512]);
        img.put(17, &[b'c'; 512]);
        img.link(15, 17);
        img.link(17, 0xFFFF_FFFF);
        img.put(18, &[b'd'; 512]);
        img.put(19, &[b'd'; 512]);
        img.link(18, 19);
        img.link(19, 0xFFFF_FFFF);
        img.dir(
            2,
            &[
                set("row.bin", 0x20, 13, 700, 700, true),
                set("chain.bin", 0x20, 15, 1000, 1000, false),
                set("partly.bin", 0x20, 18, 1000, 600, false),
                set("empty", 0x20, 0, 0, 0, false),
                set("a name of more than fifteen letters", 0x20, 13, 1, 1, true),
            ],
        );
        img.0
    }

    #[test]
    fn files_come_out_whether_they_are_in_a_row_or_chained_and_the_unwritten_end_is_zeros() {
        let (e, end) = walked(&mixed(), Limits::default());
        end.unwrap();
        let by = |n: &str| e.iter().find(|x| x.0 == n).unwrap();
        assert_eq!(by("row.bin").1, [vec![b'a'; 512], vec![b'b'; 188]].concat());
        assert_eq!(by("chain.bin").1, vec![b'c'; 1000]);
        assert_eq!(
            by("partly.bin").1,
            [vec![b'd'; 600], vec![0u8; 400]].concat()
        );
        assert_eq!(by("empty").1, b"");
        assert_eq!(by("a name of more than fifteen letters").1, b"a");
        assert!(e.iter().all(|x| x.2.is_none()));
    }

    #[test]
    fn folders_are_walked_once_and_a_folder_that_names_itself_does_not_loop() {
        let mut img = Img::new();
        img.link(3, 0xFFFF_FFFF);
        img.link(4, 0xFFFF_FFFF);
        img.put(5, b"deep");
        img.link(5, 0xFFFF_FFFF);
        img.dir(
            2,
            &[
                set("sub", 0x10, 3, 512, 512, false),
                // The same folder under another name.
                set("again", 0x10, 3, 512, 512, false),
            ],
        );
        img.put(
            3,
            &[
                set("inner", 0x10, 4, 512, 512, false),
                set("self", 0x10, 3, 512, 512, false),
                set("root", 0x10, 2, 512, 512, false),
            ]
            .iter()
            .flatten()
            .flatten()
            .copied()
            .collect::<Vec<u8>>(),
        );
        img.put(4, &set("deep.txt", 0x20, 5, 4, 4, false).concat());
        let (e, end) = walked(&img.0, Limits::default());
        end.unwrap();
        let names: Vec<_> = e.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(names, ["sub/inner/deep.txt"]);
    }

    #[test]
    fn an_entry_set_that_is_not_one_is_not_a_file() {
        let mut img = Img::new();
        img.put(3, &[b'x'; 512]);
        let good = set("good", 0x20, 3, 5, 5, true);
        // A file entry with its stream cut off by an entry of another kind.
        let mut cut = set("cut", 0x20, 3, 5, 5, true);
        cut.truncate(1);
        let mut other = [0u8; 32];
        other[0] = 0x83;
        // A secondary entry with no file entry before it.
        let mut orphan = set("orphan", 0x20, 3, 5, 5, true);
        orphan.remove(0);
        // A set that begins with a name, not a stream.
        let mut nameless = set("nameless", 0x20, 3, 5, 5, true);
        nameless.swap(1, 2);
        // Entries not in use.
        let mut unused = set("unused", 0x20, 3, 5, 5, true);
        for e in &mut unused {
            e[0] &= 0x7F;
        }
        img.dir(2, &[cut, vec![other], orphan, nameless, unused, good]);
        let (e, end) = walked(&img.0, Limits::default());
        end.unwrap();
        let names: Vec<_> = e.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(names, ["good"]);
    }

    #[test]
    fn a_chain_that_ends_early_is_a_file_cut_short() {
        let mut img = Img::new();
        img.put(3, &[b'x'; 512]);
        img.link(3, 0xFFFF_FFFF);
        img.dir(2, &[set("short", 0x20, 3, 1500, 1500, false)]);
        let (e, end) = walked(&img.0, Limits::default());
        end.unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].2, Some("file could not be read from the volume"));
        assert_eq!(e[0].1.len(), 512);
    }

    #[test]
    fn the_entry_past_the_member_limit_is_counted_and_stops_the_walk() {
        let mut img = Img::new();
        img.dir(
            2,
            &[
                set("a", 0x20, 0, 0, 0, false),
                set("b", 0x20, 0, 0, 0, false),
                set("c", 0x20, 0, 0, 0, false),
            ],
        );
        let run = |max: u64| {
            let limits = Limits {
                max_members: max,
                ..Limits::default()
            };
            walked(&img.0, limits)
        };
        let (e, end) = run(3);
        end.unwrap();
        assert_eq!(e.len(), 3);
        let (e, end) = run(2);
        assert!(!end.unwrap_err().is_corrupt());
        assert_eq!(e.len(), 2);
    }

    /// A [`Fill`] that gives its chunks one at a time.
    struct Chunks(std::vec::IntoIter<Vec<u8>>);

    impl Fill for Chunks {
        fn fill(&mut self, _: &mut Vol, out: &mut Vec<u8>) -> Step {
            match self.0.next() {
                Some(c) => {
                    out.extend_from_slice(&c);
                    Step::More
                }
                None => Step::End,
            }
        }
    }

    #[test]
    fn what_is_past_the_valid_length_is_zeros_whichever_chunk_it_falls_in() {
        let mut disk = Cursor::new(Vec::new());
        let mut v = Vol {
            disk: &mut disk,
            len: 0,
            max: 0,
        };
        let chunks = vec![vec![1u8; 4], vec![2u8; 4], vec![3u8; 4]];
        for (valid, want) in [
            (0u64, [0u8; 12].to_vec()),
            (3, [vec![1; 3], vec![0; 9]].concat()),
            (4, [vec![1; 4], vec![0; 8]].concat()),
            (6, [vec![1; 4], vec![2; 2], vec![0; 6]].concat()),
            (12, [vec![1; 4], vec![2; 4], vec![3; 4]].concat()),
        ] {
            let mut fill = Valid {
                inner: Chunks(chunks.clone().into_iter()),
                at: 0,
                valid,
            };
            let mut out = Vec::new();
            while fill.fill(&mut v, &mut out) == Step::More {}
            assert_eq!(out, want, "valid {valid}");
        }
    }

    #[test]
    fn files_over_the_buffer_limit_are_read_as_they_go_and_come_out_as_they_do_held() {
        let d = mixed();
        let (held, end) = walked(&d, Limits::default());
        end.unwrap();
        let limits = Limits {
            max_buffer_bytes: 100,
            ..Limits::default()
        };
        let mut budget = Budget::new(limits);
        let len = d.len() as u64;
        let (e, end) = collected(|emit| walk_volume(Cursor::new(&d[..]), len, &mut budget, emit));
        end.unwrap();
        assert_eq!(e.len(), held.len());
        for ((entry, streamed), (name, data, _)) in e.iter().zip(&held) {
            assert_eq!((&entry.name, &entry.data), (name, data));
            assert_eq!(*streamed, data.len() > 100, "{name}");
            assert_eq!(entry.unsupported, None, "{name}");
        }
        assert!(e.iter().filter(|(_, streamed)| *streamed).count() >= 3);
    }

    #[test]
    fn a_boot_sector_that_describes_no_volume_is_not_opened() {
        // What is written, and where.
        let edits: [(&str, usize, &[u8]); 10] = [
            ("a FAT parameter where zeros are", 20, &[1]),
            ("a revision of another major number", 105, &[2]),
            ("sectors of 256", 108, &[8]),
            ("sectors of 8 KiB", 108, &[13]),
            ("a cluster past 32 MiB", 109, &[17]),
            ("three tables", 110, &[3]),
            ("no tables", 110, &[0]),
            ("no table length", 84, &[0, 0, 0, 0]),
            ("a root outside the clusters", 96, &[200, 0, 0, 0]),
            ("a heap past the volume", 88, &[0xFF, 0xFF, 0, 0]),
        ];
        for (what, at, bytes) in edits {
            let mut d = Img::new().0;
            d[at..at + bytes.len()].copy_from_slice(bytes);
            let (e, end) = walked(&d, Limits::default());
            assert!(e.is_empty(), "{what}");
            // A boot sector that is not exFAT's is no volume; one that is and
            // cannot be used is damage.
            if is_exfat(&d) {
                assert!(end.unwrap_err().is_corrupt(), "{what}");
            }
        }
    }

    #[test]
    fn the_second_table_is_the_one_in_use_when_the_flags_say_so() {
        let mut img = Img::new();
        img.0[110] = 2;
        let table = |img: &Img| {
            let mut d = img.0.clone();
            let len = d.len() as u64;
            let mut cur = Cursor::new(&mut d[..]);
            let mut v = Vol {
                disk: &mut cur,
                len,
                max: 1 << 20,
            };
            open(&mut v).map(|f| f.table)
        };
        assert_eq!(table(&img), Some(512));
        img.0[106] = 1;
        assert_eq!(table(&img), Some(512 + 4 * 512));
    }

    #[test]
    fn a_timestamp_is_wall_clock_or_none() {
        let t: u32 = (44 << 25) | (3 << 21) | (5 << 16) | (14 << 11) | (30 << 5) | 6;
        assert_eq!(
            timestamp(t),
            Some(Mtime::Local {
                year: 2024,
                month: 3,
                day: 5,
                hour: 14,
                minute: 30,
                second: 12
            })
        );
        assert_eq!(timestamp(0), None);
        assert_eq!(timestamp(t & !(0xF << 21)), None);
        assert_eq!(timestamp((t & !(0x1F << 11)) | (25 << 11)), None);
    }
}
