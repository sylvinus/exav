//! A lenient reader of OLE2 compound files ([MS-CFB]): the container of
//! Word, Excel and PowerPoint 97 to 2003 files, of Publisher and Visio files,
//! of Windows Installer databases, of the package a password-protected OOXML
//! file hides in, and of the objects other files embed.
//!
//! It reads damaged files a strict reader refuses (a partial last sector,
//! header counts that are garbage, a directory tree out of order, chains that
//! end early) and gives what it finds: Office writes such files, and so does
//! malware. Every chain is bounded by the sectors the file has and visits a
//! sector once, so a cycle ends it, and nothing read is larger than the file.
//!
//! This is the only compound file reader of the workspace: the scanner walks
//! [`Compound::streams`] and reads each with a cap, the converters of
//! exav-render ask for the streams they know by name.
//!
//! The file is in memory ([`Compound::open`]) or read through a source
//! ([`Compound::open_source`]). Either way the FAT, the miniFAT and the mini
//! stream are not copied: what is held is the list of the FAT's sectors, the
//! sectors of the miniFAT's and the mini stream's chains, and the directory.
//! A chain is followed by reading the FAT where it is, and a stream can be
//! read as it goes ([`Compound::reader`]).

use crate::source::ByteSource;
use std::borrow::Cow;

/// The first eight bytes of a compound file.
pub const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const MAXREGSECT: u32 = 0xFFFF_FFFA;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// The most a [`StreamReader`] reads from the file at once, over sectors
/// that follow each other.
const RUN_BYTES: usize = 64 * 1024;
#[cfg(any(test, feature = "test-util"))]
const NOSTREAM: u32 = 0xFFFF_FFFF;
/// Streams under this size live in the mini stream ([MS-CFB] 2.2: the header
/// field MUST be 4096; damaged files have anything there).
const MINI_CUTOFF: u64 = 4096;
/// The longest a directory entry name is, in UTF-16 code units, terminator
/// included.
const NAME_UNITS: usize = 32;

const STORAGE: u8 = 1;
const STREAM: u8 = 2;
const ROOT: u8 = 5;

struct Entry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

/// Where a compound file's bytes are.
#[derive(Clone, Copy)]
enum Data<'a> {
    Mem(&'a [u8]),
    Src(&'a dyn ByteSource),
}

impl<'a> Data<'a> {
    fn len(self) -> usize {
        match self {
            Data::Mem(d) => d.len(),
            Data::Src(s) => s.len(),
        }
    }

    /// Up to `len` bytes from `off`, fewer where the file ends.
    fn window(self, off: usize, len: usize) -> Cow<'a, [u8]> {
        match self {
            Data::Mem(d) => {
                let end = off.saturating_add(len).min(d.len());
                Cow::Borrowed(d.get(off..end).unwrap_or(&[]))
            }
            Data::Src(s) => s.window(off, len),
        }
    }
}

/// One bit per sector, for following a chain once.
struct Seen(Vec<u64>);

impl Seen {
    fn new(n: usize) -> Seen {
        Seen(vec![0; n.div_ceil(64)])
    }

    fn has(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|w| w & (1 << (i % 64)) != 0)
    }

    /// Marks `i`, false when it was marked already.
    fn mark(&mut self, i: usize) -> bool {
        let had = self.has(i);
        if let Some(w) = self.0.get_mut(i / 64) {
            *w |= 1 << (i % 64);
        }
        !had
    }
}

/// A compound file.
pub struct Compound<'a> {
    data: Data<'a>,
    sector_size: usize,
    mini_size: usize,
    /// The FAT's sectors, in order, and the index of the first entry each
    /// holds.
    fat_sectors: Vec<u32>,
    fat_starts: Vec<usize>,
    /// Entries in the FAT, no more than the file has sectors.
    fat_len: usize,
    /// The sectors of the miniFAT's chain, and the entries it has.
    minifat_chain: Vec<u32>,
    minifat_len: usize,
    /// The sectors of the mini stream's chain, and its length.
    mini_chain: Vec<u32>,
    mini_len: u64,
    entries: Vec<Entry>,
    /// The path of each entry from the root (`/Macros/VBA/dir`) where the tree
    /// reaches it, else its bare name.
    paths: Vec<String>,
    root: usize,
    /// The directory or the mini stream is longer than the cap the file was
    /// opened with, and was read only up to it.
    cut: bool,
}

/// A stream read as it goes ([`Compound::reader`]): a run of sectors at a
/// time, the FAT read where it is.
pub struct StreamReader<'c, 'a> {
    comp: &'c Compound<'a>,
    next: u32,
    left: u64,
    seen: Seen,
    buf: Cow<'a, [u8]>,
    at: usize,
}

impl std::io::Read for StreamReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at >= self.buf.len() {
            if self.left == 0 {
                return Ok(0);
            }
            match self.next_run() {
                Some(run) if !run.is_empty() => {
                    self.buf = run;
                    self.at = 0;
                }
                _ => {
                    self.left = 0;
                    return Ok(0);
                }
            }
        }
        let n = (self.buf.len() - self.at).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

impl<'a> StreamReader<'_, 'a> {
    /// The next sectors of the chain that follow each other in the file, read
    /// in one window, no more than what is left of the stream.
    fn next_run(&mut self) -> Option<Cow<'a, [u8]>> {
        let c = self.comp;
        let ss = c.sector_size;
        let valid = |s: u32, seen: &Seen| {
            s <= MAXREGSECT && (s as usize) < c.fat_len && !seen.has(s as usize)
        };
        let first = self.next;
        if !valid(first, &self.seen) {
            return None;
        }
        self.seen.mark(first as usize);
        let mut last = first;
        let mut count = 1usize;
        let mut next = c.fat_entry(first as usize).unwrap_or(ENDOFCHAIN);
        while count * ss < RUN_BYTES
            && ((count * ss) as u64) < self.left
            && next == last.wrapping_add(1)
            && valid(next, &self.seen)
        {
            self.seen.mark(next as usize);
            last = next;
            count += 1;
            next = c.fat_entry(next as usize).unwrap_or(ENDOFCHAIN);
        }
        self.next = next;
        let want = ((count * ss) as u64).min(self.left) as usize;
        let run = c.data.window(c.sector_offset(first)?, want);
        // Short only where the file ends or the source failed: nothing
        // further of the chain is there.
        if run.len() < want {
            self.left = 0;
        } else {
            self.left -= want as u64;
        }
        Some(run)
    }
}

/// One stream of the directory.
#[derive(Clone, Copy, Debug)]
pub struct StreamInfo<'c> {
    /// Where [`Compound::read`] finds it.
    pub index: usize,
    /// Its path from the root, `/` before each name.
    pub path: &'c str,
    /// Its own name.
    pub name: &'c str,
    /// The size its directory entry declares.
    pub size: u64,
}

/// What [`Compound::read`] gives.
pub struct Stream<'a> {
    /// The stream's bytes, as far as its chain goes and the cap allows.
    pub data: Cow<'a, [u8]>,
    /// The stream is larger than the cap and `data` is its start.
    pub truncated: bool,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> Compound<'a> {
    /// `None` when `data` is not a compound file or nothing of its directory
    /// can be read.
    pub fn open(data: &'a [u8]) -> Option<Compound<'a>> {
        Self::open_in(Data::Mem(data), u64::MAX)
    }

    /// As [`Compound::open`], over a source, holding no more than `cap` bytes
    /// of the directory and no more of the mini stream than `cap` bytes reach
    /// ([`Compound::cut`] says when one was longer).
    pub fn open_source(src: &'a dyn ByteSource, cap: u64) -> Option<Compound<'a>> {
        Self::open_in(Data::Src(src), cap)
    }

    fn open_in(data: Data<'a>, cap: u64) -> Option<Compound<'a>> {
        let header = data.window(0, 512);
        if data.len() < 512 || header.len() < 512 || header[..8] != SIGNATURE {
            return None;
        }
        let shift = u16_at(&header, 30);
        if !(7..=24).contains(&shift) {
            return None;
        }
        let mini_shift = u16_at(&header, 32);
        if !(3..=12).contains(&mini_shift) {
            return None;
        }
        let sector_size = 1usize << shift;
        let v4 = u16_at(&header, 26) >= 4;
        let mut c = Compound {
            data,
            sector_size,
            mini_size: 1usize << mini_shift,
            fat_sectors: vec![],
            fat_starts: vec![],
            fat_len: 0,
            minifat_chain: vec![],
            minifat_len: 0,
            mini_chain: vec![],
            mini_len: 0,
            entries: vec![],
            paths: vec![],
            root: 0,
            cut: false,
        };
        let sectors = c.sector_count();

        // The FAT's sectors: the header's 109, then the DIFAT chain, until
        // they hold an entry for every sector of the file.
        let mut fat_len = 0usize;
        let mut add = |c: &mut Compound<'a>, s: u32| {
            if s <= MAXREGSECT && (s as usize) < sectors {
                c.fat_sectors.push(s);
                c.fat_starts.push(fat_len);
                fat_len += c.sector_len(s) / 4;
            }
            fat_len >= sectors
        };
        let mut full = (0..109).any(|i| add(&mut c, u32_at(&header, 76 + i * 4)));
        let mut seen = Seen::new(sectors);
        let mut difat = u32_at(&header, 68);
        let per = sector_size / 4;
        while !full && difat <= MAXREGSECT && (difat as usize) < sectors {
            if !seen.mark(difat as usize) {
                break;
            }
            let Some(sec) = c.sector(difat) else { break };
            full = (0..per - 1).any(|i| add(&mut c, u32_at(&sec, i * 4)));
            difat = u32_at(&sec, (per - 1) * 4);
        }
        c.fat_len = fat_len.min(sectors);
        if c.fat_len == 0 {
            return None;
        }

        let mut dir = c.read_chain(u32_at(&header, 48), cap.saturating_add(1), false);
        if dir.len() as u64 > cap {
            c.cut = true;
            dir.truncate(cap as usize);
        }
        for e in dir.as_chunks::<128>().0 {
            let units = (usize::from(u16_at(e, 64)) / 2).min(NAME_UNITS);
            let name: Vec<u16> = (0..units)
                .map(|i| u16_at(e, i * 2))
                .take_while(|&u| u != 0)
                .collect();
            let size = if v4 {
                u64::from(u32_at(e, 120)) | u64::from(u32_at(e, 124)) << 32
            } else {
                u64::from(u32_at(e, 120))
            };
            c.entries.push(Entry {
                name: String::from_utf16_lossy(&name),
                kind: e[66],
                left: u32_at(e, 68),
                right: u32_at(e, 72),
                child: u32_at(e, 76),
                start: u32_at(e, 116),
                size,
            });
        }
        // The root is entry 0 ([MS-CFB] 2.6.2); its type byte may be damaged.
        c.root = c
            .entries
            .iter()
            .position(|e| e.kind == ROOT)
            .or((!c.entries.is_empty()).then_some(0))?;
        // The mini stream and the miniFAT entries that index it, as the
        // sectors of their chains.
        let (start, size) = (c.entries[c.root].start, c.entries[c.root].size);
        let (chain, held) = c.chain_sectors(start, size.min(cap.saturating_add(1)));
        c.mini_len = held.min(size);
        if c.mini_len > cap {
            c.cut = true;
            c.mini_len = cap;
        }
        c.mini_chain = chain;
        let mini_sectors = c.mini_len.div_ceil(c.mini_size as u64);
        let (chain, held) = c.chain_sectors(u32_at(&header, 60), mini_sectors.saturating_mul(4));
        c.minifat_len = usize::try_from((held / 4).min(mini_sectors)).unwrap_or(usize::MAX);
        c.minifat_chain = chain;
        c.paths = c.tree_paths();
        Some(c)
    }

    /// The directory or the mini stream was longer than the cap given to
    /// [`Compound::open_source`]: what is past it was not read.
    pub fn cut(&self) -> bool {
        self.cut
    }

    fn sector_count(&self) -> usize {
        (self.data.len() - 1) / self.sector_size
    }

    /// Where sector `s` starts in the file.
    fn sector_offset(&self, s: u32) -> Option<usize> {
        (s as usize).checked_add(1)?.checked_mul(self.sector_size)
    }

    /// The bytes of sector `s` the file has, `s` one of its sectors.
    fn sector_len(&self, s: u32) -> usize {
        let off = self.sector_offset(s).unwrap_or(usize::MAX);
        self.sector_size.min(self.data.len().saturating_sub(off))
    }

    /// Sector `s`, cut short at the end of the file.
    fn sector(&self, s: u32) -> Option<Cow<'a, [u8]>> {
        let off = self.sector_offset(s)?;
        if off >= self.data.len() {
            return None;
        }
        Some(self.data.window(off, self.sector_size))
    }

    /// Entry `i` of the FAT, read where it is in the file.
    fn fat_entry(&self, i: usize) -> Option<u32> {
        if i >= self.fat_len {
            return None;
        }
        let k = self
            .fat_starts
            .partition_point(|&s| s <= i)
            .checked_sub(1)?;
        let off = self.sector_offset(self.fat_sectors[k])? + (i - self.fat_starts[k]) * 4;
        let w = self.data.window(off, 4);
        (w.len() == 4).then(|| u32_at(&w, 0))
    }

    /// Entry `i` of the miniFAT, read where it is in the file.
    fn minifat_entry(&self, i: usize) -> Option<u32> {
        if i >= self.minifat_len {
            return None;
        }
        let at = i * 4;
        let s = *self.minifat_chain.get(at / self.sector_size)?;
        let w = self
            .data
            .window(self.sector_offset(s)? + at % self.sector_size, 4);
        (w.len() == 4).then(|| u32_at(&w, 0))
    }

    /// Mini sector `i`, cut short at the end of the mini stream.
    fn mini_sector(&self, i: usize) -> Option<Cow<'a, [u8]>> {
        let off = (i as u64).checked_mul(self.mini_size as u64)?;
        if off >= self.mini_len {
            return None;
        }
        let ss = self.sector_size as u64;
        let s = *self.mini_chain.get(usize::try_from(off / ss).ok()?)?;
        let len = (self.mini_size as u64).min(self.mini_len - off) as usize;
        Some(
            self.data
                .window(self.sector_offset(s)? + (off % ss) as usize, len),
        )
    }

    /// The sectors of the chain from `start`, until they hold `size` bytes or
    /// the chain ends, and the bytes they hold.
    fn chain_sectors(&self, start: u32, size: u64) -> (Vec<u32>, u64) {
        let mut out = vec![];
        let mut held = 0u64;
        let mut seen = Seen::new(self.fat_len);
        let mut s = start;
        while s <= MAXREGSECT && held < size {
            let i = s as usize;
            if i >= self.fat_len || !seen.mark(i) {
                break;
            }
            out.push(s);
            held += self.sector_len(s) as u64;
            s = self.fat_entry(i).unwrap_or(ENDOFCHAIN);
        }
        (out, held)
    }

    /// The stream's bytes in the file when its sectors follow each other
    /// there, as writers lay streams out.
    fn contiguous(&self, start: u32, size: u64) -> Option<Cow<'a, [u8]>> {
        let size = usize::try_from(size).ok()?;
        let count = size.div_ceil(self.sector_size);
        let first = self.sector_offset(start)?;
        if first.checked_add(size)? > self.data.len() {
            return None;
        }
        let mut s = start as usize;
        for _ in 1..count {
            let next = self.fat_entry(s)? as usize;
            if next != s + 1 {
                return None;
            }
            s = next;
        }
        let w = self.data.window(first, size);
        (w.len() == size).then_some(w)
    }

    /// The chain from `start`, up to `size` bytes. `presize` reserves them
    /// first, for a size the caller bounded.
    fn read_chain(&self, start: u32, size: u64, presize: bool) -> Vec<u8> {
        // Sized once: no stream is longer than the file holds, and growing
        // a large one would hold two copies for a while.
        let cap = match presize {
            true => size.min(self.data.len() as u64) as usize + self.sector_size,
            false => 0,
        };
        let mut out = Vec::with_capacity(cap);
        let mut seen = Seen::new(self.fat_len);
        let mut s = start;
        while s <= MAXREGSECT && (out.len() as u64) < size {
            let i = s as usize;
            if i >= self.fat_len || !seen.mark(i) {
                break;
            }
            let Some(sec) = self.sector(s) else { break };
            out.extend_from_slice(&sec);
            s = self.fat_entry(i).unwrap_or(ENDOFCHAIN);
        }
        if (out.len() as u64) > size {
            out.truncate(size as usize);
        }
        out
    }

    fn read_mini_chain(&self, start: u32, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut seen = Seen::new(self.minifat_len);
        let mut s = start;
        while s <= MAXREGSECT && (out.len() as u64) < size {
            let i = s as usize;
            if i >= self.minifat_len || !seen.mark(i) {
                break;
            }
            let Some(sec) = self.mini_sector(i) else {
                break;
            };
            if sec.is_empty() {
                break;
            }
            out.extend_from_slice(&sec);
            s = self.minifat_entry(i).unwrap_or(ENDOFCHAIN);
        }
        if (out.len() as u64) > size {
            out.truncate(size as usize);
        }
        out
    }

    /// The path of each entry, from the tree: a storage's child and that
    /// child's siblings are its members. The sibling order a strict reader
    /// insists on does not matter here. An entry the walk does not reach keeps
    /// its bare name.
    fn tree_paths(&self) -> Vec<String> {
        let n = self.entries.len();
        let mut paths: Vec<Option<String>> = vec![None; n];
        let mut seen = vec![false; n];
        seen[self.root] = true;
        let mut storages = vec![(self.root, String::new())];
        while let Some((storage, base)) = storages.pop() {
            let mut members = vec![self.entries[storage].child];
            while let Some(m) = members.pop() {
                let m = m as usize;
                if m >= n || seen[m] {
                    continue;
                }
                seen[m] = true;
                let e = &self.entries[m];
                members.extend([e.left, e.right]);
                let path = format!("{base}/{}", e.name);
                if e.kind == STORAGE {
                    storages.push((m, path.clone()));
                }
                paths[m] = Some(path);
            }
        }
        paths
            .into_iter()
            .zip(&self.entries)
            .map(|(p, e)| p.unwrap_or_else(|| e.name.clone()))
            .collect()
    }

    /// The root storage's members, by walking its tree; others are found by
    /// name only when this misses them.
    fn root_members(&self) -> Vec<usize> {
        let mut out = vec![];
        let mut seen = vec![false; self.entries.len()];
        let mut stack = vec![self.entries[self.root].child];
        while let Some(i) = stack.pop() {
            let i = i as usize;
            if i >= self.entries.len() || seen[i] {
                continue;
            }
            seen[i] = true;
            out.push(i);
            stack.push(self.entries[i].left);
            stack.push(self.entries[i].right);
        }
        out
    }

    /// Every stream of the directory, in the order of its entries.
    pub fn streams(&self) -> impl Iterator<Item = StreamInfo<'_>> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.kind == STREAM)
            .map(|(index, e)| StreamInfo {
                index,
                path: &self.paths[index],
                name: &e.name,
                size: e.size,
            })
    }

    /// The stream at `index` of the directory ([`StreamInfo::index`]), as far
    /// as its chain goes, and no further than `cap` bytes: the file borrowed
    /// where the stream's sectors follow each other in it, else a copy.
    pub fn read(&self, index: usize, cap: u64) -> Stream<'a> {
        let Some(e) = self.entries.get(index) else {
            return Stream {
                data: Cow::Borrowed(&[]),
                truncated: false,
            };
        };
        let want = e.size.min(cap);
        let data = if e.size < MINI_CUTOFF {
            Cow::Owned(self.read_mini_chain(e.start, want))
        } else if let Some(d) = self.contiguous(e.start, want) {
            d
        } else {
            Cow::Owned(self.read_chain(e.start, want, true))
        };
        // A chain that ends early is short of the size, not cut by the cap:
        // there is nothing more of it in the file.
        let truncated = e.size > cap && (data.len() as u64) < e.size;
        Stream { data, truncated }
    }

    /// The stream at `index`, read as it goes: as far as its chain goes and
    /// no further than its size, without holding it.
    pub fn reader(&self, index: usize) -> StreamReader<'_, 'a> {
        let mut r = StreamReader {
            comp: self,
            next: ENDOFCHAIN,
            left: 0,
            seen: Seen::new(0),
            buf: Cow::Borrowed(&[]),
            at: 0,
        };
        let Some(e) = self.entries.get(index) else {
            return r;
        };
        if e.size < MINI_CUTOFF {
            r.buf = Cow::Owned(self.read_mini_chain(e.start, e.size));
        } else {
            r.next = e.start;
            r.left = e.size;
            r.seen = Seen::new(self.fat_len);
        }
        r
    }

    /// The first of `names` that names a stream at the root (else anywhere),
    /// read whole or as far as its chain goes.
    pub fn stream(&self, names: &[&str]) -> Option<Vec<u8>> {
        self.stream_ref(names).map(Cow::into_owned)
    }

    /// As [`Compound::stream`], borrowing the file's bytes when the
    /// stream's sectors follow each other in it (no copy of a large
    /// stream), else read into a copy.
    pub fn stream_ref(&self, names: &[&str]) -> Option<Cow<'a, [u8]>> {
        let members = self.root_members();
        for want in names {
            let hit = members
                .iter()
                .copied()
                .find(|&i| {
                    self.entries[i].kind == STREAM
                        && self.entries[i].name.eq_ignore_ascii_case(want)
                })
                .or_else(|| {
                    self.entries
                        .iter()
                        .position(|e| e.kind == STREAM && e.name.eq_ignore_ascii_case(want))
                })
                .or_else(|| {
                    // A name whose terminator was lost, followed by junk.
                    self.entries.iter().position(|e| {
                        e.kind == STREAM
                            && e.name.len() > want.len()
                            && e.name.is_char_boundary(want.len())
                            && e.name[..want.len()].eq_ignore_ascii_case(want)
                            && e.name[want.len()..]
                                .chars()
                                .all(|c| !c.is_ascii_alphanumeric())
                    })
                });
            if let Some(i) = hit {
                return Some(self.read(i, u64::MAX).data);
            }
        }
        None
    }

    /// Names of the streams and storages, for diagnostics.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(|e| e.kind == STORAGE || e.kind == STREAM)
            .map(|e| e.name.as_str())
    }
}

/// A document a compound file holds, by the stream it is in. A compound file
/// may hold several (a Word document, a workbook, a presentation), each one
/// an application could show.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `WordDocument`: Word 6 to 2003.
    Word,
    /// `Workbook` or `Book`: Excel 5 to 2003.
    Workbook,
    /// `PowerPoint Document` or `PP40`: PowerPoint 95 to 2003.
    Presentation,
}

/// The documents the compound file `data` holds: Word, workbook,
/// presentation, in that order. None when it is not a compound file.
pub fn compound_kinds(data: &[u8]) -> Vec<Kind> {
    let Some(c) = Compound::open(data) else {
        return Vec::new();
    };
    let has = |n: &str| c.names().any(|s| s.eq_ignore_ascii_case(n));
    let mut kinds = Vec::new();
    if has("WordDocument") {
        kinds.push(Kind::Word);
    }
    if has("Workbook") || has("Book") {
        kinds.push(Kind::Workbook);
    }
    if has("PowerPoint Document") || has("PP40") {
        kinds.push(Kind::Presentation);
    }
    kinds
}

/// A version 3 compound file holding `streams` at its root, each in the FAT
/// (padded to 4096 bytes so) or the mini stream when shorter: for the tests of
/// what reads compound files.
#[cfg(any(test, feature = "test-util"))]
pub fn build(streams: &[(&str, &[u8])]) -> Vec<u8> {
    let ss = 512usize;
    let mut sectors: Vec<Vec<u8>> = vec![];
    let mut fat: Vec<u32> = vec![];
    let chain = |sectors: &mut Vec<Vec<u8>>, fat: &mut Vec<u32>, data: &[u8]| -> u32 {
        if data.is_empty() {
            return ENDOFCHAIN;
        }
        let first = sectors.len() as u32;
        let n = data.len().div_ceil(ss);
        for k in 0..n {
            let mut s = data[k * ss..((k + 1) * ss).min(data.len())].to_vec();
            s.resize(ss, 0);
            sectors.push(s);
            fat.push(if k + 1 == n {
                ENDOFCHAIN
            } else {
                first + k as u32 + 1
            });
        }
        first
    };
    let mut mini = Vec::new();
    let mut minifat: Vec<u32> = vec![];
    let mut dirents: Vec<(String, u8, u32, u64)> = vec![];
    for (name, data) in streams {
        if (data.len() as u64) < MINI_CUTOFF {
            let first = (mini.len() / 64) as u32;
            let n = data.len().div_ceil(64);
            for k in 0..n {
                let mut s = data[k * 64..((k + 1) * 64).min(data.len())].to_vec();
                s.resize(64, 0);
                mini.extend_from_slice(&s);
                minifat.push(if k + 1 == n {
                    ENDOFCHAIN
                } else {
                    first + k as u32 + 1
                });
            }
            dirents.push((
                name.to_string(),
                STREAM,
                if n == 0 { ENDOFCHAIN } else { first },
                data.len() as u64,
            ));
        } else {
            let s = chain(&mut sectors, &mut fat, data);
            dirents.push((name.to_string(), STREAM, s, data.len() as u64));
        }
    }
    let mini_start = chain(&mut sectors, &mut fat, &mini);
    let mf: Vec<u8> = minifat.iter().flat_map(|v| v.to_le_bytes()).collect();
    let minifat_start = chain(&mut sectors, &mut fat, &mf);
    let mut dir = Vec::new();
    let mut entry = |name: &str, kind: u8, child: u32, right: u32, start: u32, size: u64| {
        let mut e = vec![0u8; 128];
        let u: Vec<u16> = name.encode_utf16().chain([0]).collect();
        for (i, x) in u.iter().enumerate() {
            e[i * 2..i * 2 + 2].copy_from_slice(&x.to_le_bytes());
        }
        e[64..66].copy_from_slice(&((u.len() * 2) as u16).to_le_bytes());
        e[66] = kind;
        e[68..72].copy_from_slice(&NOSTREAM.to_le_bytes());
        e[72..76].copy_from_slice(&right.to_le_bytes());
        e[76..80].copy_from_slice(&child.to_le_bytes());
        e[116..120].copy_from_slice(&start.to_le_bytes());
        e[120..124].copy_from_slice(&(size as u32).to_le_bytes());
        dir.extend_from_slice(&e);
    };
    entry(
        "Root Entry",
        ROOT,
        if dirents.is_empty() { NOSTREAM } else { 1 },
        NOSTREAM,
        mini_start,
        mini.len() as u64,
    );
    for (k, (name, kind, start, size)) in dirents.iter().enumerate() {
        let right = if k + 1 < dirents.len() {
            k as u32 + 2
        } else {
            NOSTREAM
        };
        entry(name, *kind, NOSTREAM, right, *start, *size);
    }
    let dir_start = chain(&mut sectors, &mut fat, &dir);
    // The FAT's own sectors, marked 0xFFFFFFFD.
    let n_fat = (fat.len() + 1).div_ceil(128).max(1);
    let fat_first = sectors.len() as u32;
    fat.extend(std::iter::repeat_n(0xFFFF_FFFD, n_fat));
    let mut fatb: Vec<u8> = fat.iter().flat_map(|v| v.to_le_bytes()).collect();
    fatb.resize(n_fat * ss, 0xFF);
    for k in 0..n_fat {
        sectors.push(fatb[k * ss..(k + 1) * ss].to_vec());
    }
    let mut h = vec![0u8; 512];
    h[..8].copy_from_slice(&SIGNATURE);
    h[24..26].copy_from_slice(&0x3Eu16.to_le_bytes());
    h[26..28].copy_from_slice(&3u16.to_le_bytes());
    h[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
    h[30..32].copy_from_slice(&9u16.to_le_bytes());
    h[32..34].copy_from_slice(&6u16.to_le_bytes());
    h[44..48].copy_from_slice(&(n_fat as u32).to_le_bytes());
    h[48..52].copy_from_slice(&dir_start.to_le_bytes());
    h[56..60].copy_from_slice(&4096u32.to_le_bytes());
    h[60..64].copy_from_slice(&minifat_start.to_le_bytes());
    h[64..68].copy_from_slice(&(minifat.len().div_ceil(128) as u32).to_le_bytes());
    h[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    for i in 0..109 {
        let v = if i < n_fat {
            fat_first + i as u32
        } else {
            NOSTREAM
        };
        h[76 + i * 4..80 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    let mut out = h;
    for s in sectors {
        out.extend_from_slice(&s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fat_and_mini_streams() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        // In the strict reader's order: shorter names first.
        let file = build(&[("small", b"hello"), ("Workbook", &big)]);
        let c = Compound::open(&file).unwrap();
        assert_eq!(c.stream(&["WORKBOOK"]).unwrap(), big);
        assert_eq!(c.stream(&["nope", "Small"]).unwrap(), b"hello");
        assert!(c.stream(&["nope"]).is_none());
        // The strict reader agrees.
        let mut s = ::cfb::CompoundFile::open(std::io::Cursor::new(&file)).unwrap();
        let mut v = vec![];
        std::io::Read::read_to_end(&mut s.open_stream("/Workbook").unwrap(), &mut v).unwrap();
        assert_eq!(v, big);
    }

    #[test]
    fn streams_in_order_are_borrowed() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 13) as u8).collect();
        let mut file = build(&[("Pictures", &big)]);
        let c = Compound::open(&file).unwrap();
        let s = c.stream_ref(&["Pictures"]).unwrap();
        assert!(matches!(s, Cow::Borrowed(_)));
        assert_eq!(s, &big[..]);
        // Its chain out of order: a copy of what the chain gives.
        let fat_sector = u32_at(&file, 76) as usize;
        let off = (fat_sector + 1) * 512;
        file[off..off + 4].copy_from_slice(&2u32.to_le_bytes());
        file[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes());
        file[off + 4..off + 8].copy_from_slice(&3u32.to_le_bytes());
        let c = Compound::open(&file).unwrap();
        let s = c.stream_ref(&["Pictures"]).unwrap();
        assert!(matches!(s, Cow::Owned(_)));
        assert_eq!(s[..512], big[..512]);
        assert_eq!(s[512..1024], big[1024..1536]);
        assert_eq!(s[1024..1536], big[512..1024]);
    }

    #[test]
    fn damaged_files_give_what_is_there() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 7) as u8).collect();
        let mut file = build(&[("Workbook", &big)]);
        // Garbage in the header's counts and cutoff.
        file[44..48].copy_from_slice(&0x2020_2020u32.to_le_bytes());
        file[56..60].copy_from_slice(&0x2020_2020u32.to_le_bytes());
        let c = Compound::open(&file).unwrap();
        assert_eq!(c.stream(&["Workbook"]).unwrap(), big);
        // A FAT chain made a cycle: it ends where it loops.
        let mut cyc = file.clone();
        let fat_sector = u32_at(&cyc, 76) as usize;
        let off = (fat_sector + 1) * 512;
        cyc[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
        let c = Compound::open(&cyc).unwrap();
        assert_eq!(c.stream(&["Workbook"]).unwrap(), big[..1024]);
        // Truncated through the stream: no panic, no directory.
        for n in [600, 3000, file.len() - 100] {
            let _ = Compound::open(&file[..n]).and_then(|c| c.stream(&["Workbook"]));
        }
    }

    #[test]
    fn damaged_root_type_and_unterminated_names() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 11) as u8).collect();
        let mut file = build(&[("Workbook", &big)]);
        let dir = (u32_at(&file, 48) as usize + 1) * 512;
        // The root's type byte damaged.
        file[dir + 66] = 0xF8;
        // The stream's name without its terminator, padded with junk.
        let e = dir + 128;
        for i in 8..32 {
            file[e + i * 2..e + i * 2 + 2].copy_from_slice(&0x2020u16.to_le_bytes());
        }
        file[e + 64..e + 66].copy_from_slice(&64u16.to_le_bytes());
        let c = Compound::open(&file).unwrap();
        assert_eq!(c.stream(&["Workbook"]).unwrap(), big);
        assert!(c.stream(&["Work"]).is_none());
    }

    /// The scanner's view: every stream with its path, each read under a cap
    /// that says when it cut one.
    #[test]
    fn streams_are_listed_with_their_paths_and_read_under_a_cap() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 5) as u8).collect();
        let file = build(&[("a", b"hello"), ("Big", &big)]);
        let c = Compound::open(&file).unwrap();
        let listed: Vec<_> = c.streams().map(|s| (s.path.to_string(), s.size)).collect();
        assert_eq!(
            listed,
            [("/a".to_string(), 5), ("/Big".to_string(), 10_000)]
        );
        let big_at = c.streams().find(|s| s.name == "Big").unwrap().index;
        let cut = c.read(big_at, 4000);
        assert!(cut.truncated);
        assert_eq!(&cut.data[..], &big[..4000]);
        let whole = c.read(big_at, 10_000);
        assert!(!whole.truncated);
        assert_eq!(&whole.data[..], &big[..]);
        // A chain that ends early is short, not cut by the cap.
        let mut file = file;
        let dir = (u32_at(&file, 48) as usize + 1) * 512;
        file[dir + 128 * 2 + 120..dir + 128 * 2 + 124].copy_from_slice(&20_000u32.to_le_bytes());
        let c = Compound::open(&file).unwrap();
        let short = c.read(big_at, u64::MAX);
        assert!(!short.truncated);
        assert!(short.data.len() < 20_000);
    }

    /// Storages give their streams a path, and an entry no storage reaches
    /// keeps its bare name.
    #[test]
    fn paths_follow_the_tree_of_storages() {
        let file = std::io::Cursor::new(Vec::new());
        let mut w = ::cfb::CompoundFile::create(file).unwrap();
        w.create_storage("/Macros").unwrap();
        w.create_storage("/Macros/VBA").unwrap();
        for (path, body) in [("/Macros/VBA/dir", &b"x"[..]), ("/top", &b"y"[..])] {
            std::io::Write::write_all(&mut w.create_stream(path).unwrap(), body).unwrap();
        }
        w.flush().unwrap();
        let bytes = w.into_inner().into_inner();
        let c = Compound::open(&bytes).unwrap();
        let mut paths: Vec<_> = c.streams().map(|s| s.path.to_string()).collect();
        paths.sort();
        assert_eq!(paths, ["/Macros/VBA/dir", "/top"]);
        assert_eq!(c.stream(&["top"]).unwrap(), b"y");
        assert_eq!(c.stream(&["dir"]).unwrap(), b"x");
    }

    fn cache(file: &[u8]) -> crate::source::BlockCache<std::io::Cursor<Vec<u8>>> {
        crate::source::BlockCache::with_sizes(std::io::Cursor::new(file.to_vec()), 512, 4096)
            .unwrap()
    }

    fn read_all(mut r: impl std::io::Read) -> Vec<u8> {
        let mut v = vec![];
        r.read_to_end(&mut v).unwrap();
        v
    }

    /// Over a source as in memory: the same streams, read whole or as they
    /// go, in a file large enough that its FAT continues in the DIFAT.
    #[test]
    fn a_source_reads_as_memory_does() {
        let mut w = ::cfb::CompoundFile::create_with_version(
            ::cfb::Version::V3,
            std::io::Cursor::new(Vec::new()),
        )
        .unwrap();
        let big: Vec<u8> = (0..8_000_000u32).map(|i| (i % 253) as u8).collect();
        w.create_storage("/S").unwrap();
        for (path, body) in [
            ("/small", &b"hello"[..]),
            ("/S/mid", &big[..5000]),
            ("/big", &big[..]),
            ("/S/tiny", &b"x"[..]),
        ] {
            std::io::Write::write_all(&mut w.create_stream(path).unwrap(), body).unwrap();
        }
        w.flush().unwrap();
        let file = w.into_inner().into_inner();
        // 109 FAT sectors hold 13,952 sectors of 512 bytes: past that, the
        // DIFAT.
        assert!(file.len() > 109 * 128 * 512);
        let src = cache(&file);
        let mem = Compound::open(&file).unwrap();
        let s = Compound::open_source(&src, u64::MAX).unwrap();
        assert!(!s.cut());
        let a: Vec<_> = mem
            .streams()
            .map(|x| (x.path.to_string(), x.size))
            .collect();
        let b: Vec<_> = s.streams().map(|x| (x.path.to_string(), x.size)).collect();
        assert_eq!(a, b);
        assert_eq!(a.len(), 4);
        for info in mem.streams() {
            let whole = mem.read(info.index, u64::MAX).data.into_owned();
            assert_eq!(whole.len() as u64, info.size, "{}", info.path);
            assert_eq!(s.read(info.index, u64::MAX).data, whole, "{}", info.path);
            assert_eq!(read_all(s.reader(info.index)), whole, "{}", info.path);
            assert_eq!(read_all(mem.reader(info.index)), whole, "{}", info.path);
        }
        assert_eq!(s.stream(&["big"]).unwrap(), big);
    }

    /// A stream read as it goes follows its chain as a whole read does: out of
    /// order, and ending where it loops.
    #[test]
    fn a_reader_follows_chains_out_of_order_and_stops_at_a_cycle() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 13) as u8).collect();
        let mut file = build(&[("Pictures", &big)]);
        let fat_sector = u32_at(&file, 76) as usize;
        let off = (fat_sector + 1) * 512;
        file[off..off + 4].copy_from_slice(&2u32.to_le_bytes());
        file[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes());
        file[off + 4..off + 8].copy_from_slice(&3u32.to_le_bytes());
        let src = cache(&file);
        let c = Compound::open_source(&src, u64::MAX).unwrap();
        let i = c.streams().next().unwrap().index;
        let whole = c.read(i, u64::MAX).data.into_owned();
        assert_eq!(whole.len(), big.len());
        assert_eq!(read_all(c.reader(i)), whole);
        // Sector 3 back to sector 0.
        file[off + 12..off + 16].copy_from_slice(&0u32.to_le_bytes());
        let src = cache(&file);
        let c = Compound::open_source(&src, u64::MAX).unwrap();
        let got = read_all(c.reader(i));
        assert_eq!(got, c.read(i, u64::MAX).data.into_owned());
        assert_eq!(got.len(), 2048);
    }

    /// A directory longer than the cap is read up to it, and says so.
    #[test]
    fn a_directory_past_the_cap_is_cut() {
        let names: Vec<String> = (0..40).map(|i| format!("s{i:02}")).collect();
        let streams: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let file = build(&streams);
        let src = cache(&file);
        let c = Compound::open_source(&src, 128 * 10).unwrap();
        assert!(c.cut());
        assert!(c.streams().count() < 40);
        let c = Compound::open_source(&src, 1 << 20).unwrap();
        assert!(!c.cut());
        assert_eq!(c.streams().count(), 40);
    }

    #[test]
    fn each_document_of_a_compound_file_is_named() {
        let both = build(&[
            ("WordDocument", &[0u8; 64][..]),
            ("PowerPoint Document", &[0u8; 64][..]),
        ]);
        assert_eq!(compound_kinds(&both), [Kind::Word, Kind::Presentation]);
        let book = build(&[("Book", &[0u8; 64][..])]);
        assert_eq!(compound_kinds(&book), [Kind::Workbook]);
        assert!(compound_kinds(b"not a compound file").is_empty());
    }

    /// The kinds come in one order, whatever the order of the directory.
    #[test]
    fn a_workbook_and_a_word_stream_are_named_word_first() {
        let file = build(&[
            ("Workbook", &[0u8; 64][..]),
            ("WordDocument", &[0u8; 64][..]),
        ]);
        assert_eq!(compound_kinds(&file), [Kind::Word, Kind::Workbook]);
        // Names compare without regard to ASCII case.
        let file = build(&[("pp40", &[0u8; 64][..]), ("BOOK", &[0u8; 64][..])]);
        assert_eq!(compound_kinds(&file), [Kind::Workbook, Kind::Presentation]);
    }

    /// A stream's name written inside another stream is not a stream of the
    /// directory.
    #[test]
    fn a_name_quoted_in_a_stream_is_not_a_document() {
        let mut quote = Vec::new();
        for c in "WordDocument".encode_utf16() {
            quote.extend_from_slice(&c.to_le_bytes());
        }
        quote.resize(64, 0);
        quote.extend_from_slice(&[26, 0, 2, 0]);
        let file = build(&[("Notes", &quote[..])]);
        assert!(compound_kinds(&file).is_empty());
    }
}
