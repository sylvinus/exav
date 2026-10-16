//! A lenient reader of OLE2 compound files ([MS-CFB]), for the streams an
//! XLS or PPT file keeps its document in. It reads damaged files a strict reader
//! refuses (a partial last sector, header counts that are garbage, a
//! directory tree out of order, chains that end early) and gives what it
//! finds. Every chain is bounded by the sectors the file has, and visits a
//! sector once, so a cycle ends it and nothing read is larger than the file.

use super::bytes::{u16_at, u32_at};
use std::borrow::Cow;

pub const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MAXREGSECT: u32 = 0xFFFF_FFFA;
#[cfg(any(test, feature = "office-test-util"))]
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// Streams under this size live in the mini stream ([MS-CFB] 2.2: the
/// header field MUST be 4096; damaged files have anything there).
const MINI_CUTOFF: u64 = 4096;

struct Entry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

pub struct Compound<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_size: usize,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    mini: Vec<u8>,
    entries: Vec<Entry>,
    root: usize,
}

impl<'a> Compound<'a> {
    /// `None` when `data` is not a compound file or nothing of its
    /// directory can be read.
    pub fn open(data: &'a [u8]) -> Option<Compound<'a>> {
        if data.len() < 512 || data[..8] != SIGNATURE {
            return None;
        }
        let shift = u16_at(data, 30);
        let sector_size: usize = match shift {
            9 => 512,
            12 => 4096,
            _ => return None,
        };
        let mini_size = match u16_at(data, 32) {
            6 => 64,
            _ => return None,
        };
        let v4 = u16_at(data, 26) == 4;
        let mut c = Compound {
            data,
            sector_size,
            mini_size,
            fat: vec![],
            minifat: vec![],
            mini: vec![],
            entries: vec![],
            root: 0,
        };
        let sectors = c.sector_count();

        // The FAT's sectors: the header's 109, then the DIFAT chain.
        let mut fat_sectors: Vec<u32> = (0..109)
            .map(|i| u32_at(data, 76 + i * 4))
            .filter(|&s| s <= MAXREGSECT && (s as usize) < sectors)
            .collect();
        let mut seen = vec![false; sectors];
        let mut difat = u32_at(data, 68);
        let per = sector_size / 4;
        while difat <= MAXREGSECT && (difat as usize) < sectors && !seen[difat as usize] {
            seen[difat as usize] = true;
            let Some(sec) = c.sector(difat) else { break };
            for i in 0..per - 1 {
                let s = u32_at(sec, i * 4);
                if s <= MAXREGSECT && (s as usize) < sectors {
                    fat_sectors.push(s);
                }
            }
            difat = u32_at(sec, (per - 1) * 4);
        }
        fat_sectors.truncate(sectors);
        let mut fat = Vec::with_capacity(fat_sectors.len().min(sectors) * per);
        for &s in &fat_sectors {
            if let Some(sec) = c.sector(s) {
                fat.extend((0..sec.len() / 4).map(|i| u32_at(sec, i * 4)));
            }
            if fat.len() >= sectors {
                break;
            }
        }
        fat.truncate(sectors);
        c.fat = fat;

        let dir = c.read_chain(u32_at(data, 48), u64::MAX);
        for e in dir.as_chunks::<128>().0 {
            let len = (u16_at(e, 64) as usize).min(64);
            let units: Vec<u16> = (0..len / 2)
                .map(|i| u16_at(e, i * 2))
                .take_while(|&u| u != 0)
                .collect();
            let size = if v4 {
                u64::from(u32_at(e, 120)) | u64::from(u32_at(e, 124)) << 32
            } else {
                u64::from(u32_at(e, 120))
            };
            c.entries.push(Entry {
                name: String::from_utf16_lossy(&units),
                kind: e[66],
                left: u32_at(e, 68),
                right: u32_at(e, 72),
                child: u32_at(e, 76),
                start: u32_at(e, 116),
                size,
            });
        }
        // The root is entry 0 ([MS-CFB] 2.6.2); its type byte may be damaged.
        let root = c
            .entries
            .iter()
            .position(|e| e.kind == 5)
            .or((!c.entries.is_empty()).then_some(0))?;
        c.root = root;
        let minifat = c.read_chain(u32_at(data, 60), u64::MAX);
        c.minifat = (0..minifat.len() / 4)
            .map(|i| u32_at(&minifat, i * 4))
            .collect();
        c.mini = c.read_chain(c.entries[root].start, c.entries[root].size);
        Some(c)
    }

    fn sector_count(&self) -> usize {
        (self.data.len() - 1) / self.sector_size
    }

    /// Sector `s`, cut short at the end of the file.
    fn sector(&self, s: u32) -> Option<&'a [u8]> {
        let off = (s as usize).checked_add(1)?.checked_mul(self.sector_size)?;
        if off >= self.data.len() {
            return None;
        }
        Some(&self.data[off..(off + self.sector_size).min(self.data.len())])
    }

    /// The stream's bytes in the file when its sectors follow each other
    /// there, as writers lay streams out.
    fn contiguous(&self, start: u32, size: u64) -> Option<&'a [u8]> {
        let size = usize::try_from(size).ok()?;
        let count = size.div_ceil(self.sector_size);
        let first = (start as usize)
            .checked_add(1)?
            .checked_mul(self.sector_size)?;
        if first.checked_add(size)? > self.data.len() {
            return None;
        }
        let mut s = start as usize;
        for _ in 1..count {
            let next = *self.fat.get(s)? as usize;
            if next != s + 1 {
                return None;
            }
            s = next;
        }
        Some(&self.data[first..first + size])
    }

    fn read_chain(&self, start: u32, size: u64) -> Vec<u8> {
        // Sized once: no stream is longer than the file holds, and growing
        // a large one would hold two copies for a while.
        let cap = size.min(self.data.len() as u64) as usize + self.sector_size;
        let mut out = Vec::with_capacity(cap);
        let mut seen = vec![false; self.fat.len()];
        let mut s = start;
        while s <= MAXREGSECT && (out.len() as u64) < size {
            let i = s as usize;
            if i >= self.fat.len() || seen[i] {
                break;
            }
            seen[i] = true;
            let Some(sec) = self.sector(s) else { break };
            out.extend_from_slice(sec);
            s = self.fat[i];
        }
        if (out.len() as u64) > size {
            out.truncate(size as usize);
        }
        out
    }

    fn read_mini_chain(&self, start: u32, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut seen = vec![false; self.minifat.len()];
        let mut s = start;
        while s <= MAXREGSECT && (out.len() as u64) < size {
            let i = s as usize;
            if i >= self.minifat.len() || seen[i] {
                break;
            }
            seen[i] = true;
            let off = i * self.mini_size;
            let Some(sec) = self
                .mini
                .get(off..(off + self.mini_size).min(self.mini.len()))
            else {
                break;
            };
            if sec.is_empty() {
                break;
            }
            out.extend_from_slice(sec);
            s = self.minifat[i];
        }
        if (out.len() as u64) > size {
            out.truncate(size as usize);
        }
        out
    }

    /// The root storage's members, by walking its tree; others are found by
    /// name only when this misses them.
    fn root_members(&self) -> Vec<usize> {
        let root = self.root;
        let mut out = vec![];
        let mut seen = vec![false; self.entries.len()];
        let mut stack = vec![self.entries[root].child];
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
                    self.entries[i].kind == 2 && self.entries[i].name.eq_ignore_ascii_case(want)
                })
                .or_else(|| {
                    self.entries
                        .iter()
                        .position(|e| e.kind == 2 && e.name.eq_ignore_ascii_case(want))
                })
                .or_else(|| {
                    // A name whose terminator was lost, followed by junk.
                    self.entries.iter().position(|e| {
                        e.kind == 2
                            && e.name.len() > want.len()
                            && e.name.is_char_boundary(want.len())
                            && e.name[..want.len()].eq_ignore_ascii_case(want)
                            && e.name[want.len()..]
                                .chars()
                                .all(|c| !c.is_ascii_alphanumeric())
                    })
                });
            if let Some(i) = hit {
                let e = &self.entries[i];
                return Some(if e.size < MINI_CUTOFF {
                    Cow::Owned(self.read_mini_chain(e.start, e.size))
                } else if let Some(d) = self.contiguous(e.start, e.size) {
                    Cow::Borrowed(d)
                } else {
                    Cow::Owned(self.read_chain(e.start, e.size))
                });
            }
        }
        None
    }

    /// Names of the streams and storages, for diagnostics.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(|e| e.kind == 1 || e.kind == 2)
            .map(|e| e.name.as_str())
    }
}

#[cfg(any(test, feature = "office-test-util"))]
pub mod tests {
    use super::*;

    /// A version 3 compound file holding `streams` at its root, each in the
    /// FAT (padded to 4096 bytes so) or the mini stream when shorter.
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
                    2,
                    if n == 0 { ENDOFCHAIN } else { first },
                    data.len() as u64,
                ));
            } else {
                let s = chain(&mut sectors, &mut fat, data);
                dirents.push((name.to_string(), 2, s, data.len() as u64));
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
            e[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
            e[72..76].copy_from_slice(&right.to_le_bytes());
            e[76..80].copy_from_slice(&child.to_le_bytes());
            e[116..120].copy_from_slice(&start.to_le_bytes());
            e[120..124].copy_from_slice(&(size as u32).to_le_bytes());
            dir.extend_from_slice(&e);
        };
        entry(
            "Root Entry",
            5,
            if dirents.is_empty() { u32::MAX } else { 1 },
            u32::MAX,
            mini_start,
            mini.len() as u64,
        );
        for (k, (name, kind, start, size)) in dirents.iter().enumerate() {
            let right = if k + 1 < dirents.len() {
                k as u32 + 2
            } else {
                u32::MAX
            };
            entry(name, *kind, u32::MAX, right, *start, *size);
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
                u32::MAX
            };
            h[76 + i * 4..80 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        let mut out = h;
        for s in sectors {
            out.extend_from_slice(&s);
        }
        out
    }

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
        let mut s = cfb::CompoundFile::open(std::io::Cursor::new(&file)).unwrap();
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
}
