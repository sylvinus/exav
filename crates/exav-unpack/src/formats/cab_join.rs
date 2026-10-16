//! Cabinets of a set: one folder, one file, cut across several `.cab` files.
//!
//! A cabinet names the one before it and the one after it. A folder that runs
//! on into the next cabinet ends the first with a block cut short (`cbUncomp`
//! zero, the rest of its bytes the first block of the next cabinet), and a file
//! that straddles the two is listed in both, with the same name, size and
//! offset in the folder, as continued to the next and from the previous. The
//! layout is that of the format's published specification ([MS-CAB]); it was
//! checked on sets built to it by `cabextract`, which reads them as the files
//! they were made from.
//!
//! [`join`] puts such a set back into the one cabinet it was cut from, which
//! [`super::cab`] reads as any other: the folders that run on are one, their
//! blocks in order, and each file is listed once. Nothing is decoded here. No
//! name is turned into a path: [`links`] reports the names a cabinet's header
//! gives, for a caller to match against the names it was given.

use crate::bytes::at;

const PREV: u16 = 1;
const NEXT: u16 = 2;
const RESERVE: u16 = 4;

/// `iFolder` values that say a file runs across cabinets.
const FROM_PREV: u16 = 0xFFFD;
const TO_NEXT: u16 = 0xFFFE;
const BOTH: u16 = 0xFFFF;

/// What a cabinet's header says of its place in a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Links {
    pub set_id: u16,
    /// Zero for the first cabinet of the set.
    pub index: u16,
    /// The cabinet before it, as its header names it.
    pub prev: Option<String>,
    /// The cabinet after it.
    pub next: Option<String>,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(at(d, o, 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(at(d, o, 4)?.try_into().ok()?))
}

/// A NUL-terminated string at `o` of at most 255 bytes, and where it ends.
fn cstr(d: &[u8], o: usize) -> Option<(&[u8], usize)> {
    let rest = d.get(o..)?;
    let n = rest.iter().take(256).position(|&b| b == 0)?;
    Some((&rest[..n], o + n + 1))
}

struct Header {
    links: Links,
    flags: u16,
    folders: u16,
    files: u16,
    coff_files: usize,
    /// Where the folder records start, and the reserved bytes after each,
    /// and after each data block.
    folders_at: usize,
    cb_folder: usize,
    cb_data: usize,
}

fn header(d: &[u8]) -> Option<Header> {
    if at(d, 0, 4)? != b"MSCF" {
        return None;
    }
    let (coff_files, flags) = (u32_at(d, 16)? as usize, u16_at(d, 30)?);
    let (mut pos, mut cb_folder, mut cb_data) = (36usize, 0usize, 0usize);
    if flags & RESERVE != 0 {
        let cb_header = usize::from(u16_at(d, 36)?);
        cb_folder = usize::from(*d.get(38)?);
        cb_data = usize::from(*d.get(39)?);
        pos = 40usize.checked_add(cb_header)?;
    }
    let mut name = |wanted: bool| -> Option<Option<String>> {
        if !wanted {
            return Some(None);
        }
        let (n, after) = cstr(d, pos)?;
        // The disk's name follows, and is not wanted.
        let (_, after) = cstr(d, after)?;
        pos = after;
        Some(Some(String::from_utf8_lossy(n).into_owned()))
    };
    let prev = name(flags & PREV != 0)?;
    let next = name(flags & NEXT != 0)?;
    Some(Header {
        links: Links {
            set_id: u16_at(d, 32)?,
            index: u16_at(d, 34)?,
            prev,
            next,
        },
        flags,
        folders: u16_at(d, 26)?,
        files: u16_at(d, 28)?,
        coff_files,
        folders_at: pos,
        cb_folder,
        cb_data,
    })
}

/// What `data`, a cabinet, says of its place in a set: `None` when it is not
/// a cabinet that is part of one (no cabinet before it or after it).
pub fn links(data: &[u8]) -> Option<Links> {
    let h = header(data)?;
    (h.flags & (PREV | NEXT) != 0).then_some(h.links)
}

#[derive(Clone)]
struct Block {
    uncompressed: u16,
    payload: Vec<u8>,
}

struct Folder {
    kind: u16,
    blocks: Vec<Block>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    In(usize),
    FromPrev,
    ToNext,
    Both,
}

struct File {
    size: u32,
    offset: u32,
    place: Place,
    date: u16,
    time: u16,
    attribs: u16,
    name: Vec<u8>,
}

struct Cabinet {
    links: Links,
    folders: Vec<Folder>,
    files: Vec<File>,
}

fn parse(d: &[u8]) -> Option<Cabinet> {
    let h = header(d)?;
    let mut folders = Vec::new();
    let record = 8 + h.cb_folder;
    for i in 0..usize::from(h.folders) {
        let at_ = h.folders_at.checked_add(i.checked_mul(record)?)?;
        let (start, count, kind) = (
            u32_at(d, at_)? as usize,
            u16_at(d, at_ + 4)?,
            u16_at(d, at_ + 6)?,
        );
        let mut pos = start;
        let mut blocks = Vec::new();
        for _ in 0..count {
            let (len, uncompressed) = (usize::from(u16_at(d, pos + 4)?), u16_at(d, pos + 6)?);
            let from = pos.checked_add(8 + h.cb_data)?;
            blocks.push(Block {
                uncompressed,
                payload: at(d, from, len)?.to_vec(),
            });
            pos = from.checked_add(len)?;
        }
        folders.push(Folder { kind, blocks });
    }
    let mut files = Vec::new();
    let mut pos = h.coff_files;
    for _ in 0..h.files {
        let (size, offset, folder) = (u32_at(d, pos)?, u32_at(d, pos + 4)?, u16_at(d, pos + 8)?);
        let (name, after) = cstr(d, pos.checked_add(16)?)?;
        let place = match folder {
            FROM_PREV => Place::FromPrev,
            TO_NEXT => Place::ToNext,
            BOTH => Place::Both,
            i if usize::from(i) < folders.len() => Place::In(usize::from(i)),
            _ => return None,
        };
        files.push(File {
            size,
            offset,
            place,
            date: u16_at(d, pos + 10)?,
            time: u16_at(d, pos + 12)?,
            attribs: u16_at(d, pos + 14)?,
            name: name.to_vec(),
        });
        pos = after;
    }
    Some(Cabinet {
        links: h.links,
        folders,
        files,
    })
}

/// The cabinets of one set, in order, as the one cabinet they were cut from.
/// `Err` says what does not fit: a part that is not a cabinet, a set whose
/// ends or numbers are wrong, a folder or a file that does not continue.
pub fn join(parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    if parts.len() < 2 {
        return Err("a set of cabinets has at least two".into());
    }
    let mut cabs = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        let c = parse(p).ok_or_else(|| format!("part {} is not a readable cabinet", i + 1))?;
        let first = i == 0;
        let last = i + 1 == parts.len();
        if c.links.prev.is_some() == first || c.links.next.is_some() == last {
            return Err(format!(
                "part {} is not where its header puts it in the set",
                i + 1
            ));
        }
        let same_set = cabs
            .first()
            .is_none_or(|f: &Cabinet| f.links.set_id == c.links.set_id);
        if usize::from(c.links.index) != i || !same_set {
            return Err(format!("part {} is of another set, or out of order", i + 1));
        }
        cabs.push(c);
    }
    let mut iter = cabs.into_iter();
    let mut acc = iter.next().expect("two parts at least");
    for next in iter {
        merge(&mut acc, next)?;
    }
    if acc
        .files
        .iter()
        .any(|f| f.place != Place::In(f.folder_index()))
    {
        return Err("a file runs on past the last cabinet".into());
    }
    write(&acc)
}

impl File {
    fn folder_index(&self) -> usize {
        match self.place {
            Place::In(i) => i,
            _ => usize::MAX,
        }
    }
}

fn merge(acc: &mut Cabinet, mut next: Cabinet) -> Result<(), String> {
    let spanning = |f: &File| matches!(f.place, Place::ToNext);
    let last = acc
        .folders
        .len()
        .checked_sub(1)
        .ok_or("a cabinet with no folder")?;
    let cut_block = acc.folders[last]
        .blocks
        .last()
        .is_some_and(|b| b.uncompressed == 0);
    let continues = !next.folders.is_empty() && (cut_block || acc.files.iter().any(spanning));
    // Where each of the next cabinet's folders ends up.
    let mut folders = std::mem::take(&mut next.folders).into_iter();
    let map_from = if continues {
        let first = folders.next().expect("one at least");
        let into = &mut acc.folders[last];
        if first.kind != into.kind {
            return Err("a folder runs on in a cabinet that compresses it otherwise".into());
        }
        let mut rest = first.blocks.into_iter();
        if cut_block {
            if let Some(b) = rest.next() {
                let end = into.blocks.last_mut().expect("a cut block");
                end.payload.extend_from_slice(&b.payload);
                if end.payload.len() > usize::from(u16::MAX) {
                    return Err("a block cut across cabinets is longer than a block can be".into());
                }
                end.uncompressed = b.uncompressed;
            }
        }
        into.blocks.extend(rest);
        if into.blocks.len() > usize::from(u16::MAX) {
            return Err("a folder with more blocks than a cabinet can hold".into());
        }
        last
    } else {
        acc.folders.len()
    };
    let shift = |i: usize| if continues { last + i } else { map_from + i };
    acc.folders.extend(folders);
    if acc.folders.len() > usize::from(u16::MAX) {
        return Err("more folders than a cabinet can hold".into());
    }
    // The files left running on at the end of `acc`, each of which the next
    // cabinet must continue.
    let mut open = acc
        .files
        .iter()
        .filter(|f| f.place == Place::ToNext)
        .count();
    for f in next.files {
        match f.place {
            Place::FromPrev | Place::Both => {
                let start = acc
                    .files
                    .iter_mut()
                    .find(|a| {
                        a.place == Place::ToNext
                            && a.name == f.name
                            && a.size == f.size
                            && a.offset == f.offset
                    })
                    .ok_or("a file continued from the cabinet before is not in it")?;
                open -= 1;
                // Resolved here, unless it runs on again.
                if f.place == Place::FromPrev {
                    start.place = Place::In(last);
                }
            }
            Place::In(i) => acc.files.push(File {
                place: Place::In(shift(i)),
                ..f
            }),
            Place::ToNext => acc.files.push(File {
                place: Place::ToNext,
                ..f
            }),
        }
    }
    if open != 0 {
        return Err("a file continued to the next cabinet is not in it".into());
    }
    acc.links.next = next.links.next;
    Ok(())
}

fn write(c: &Cabinet) -> Result<Vec<u8>, String> {
    let too_big = || "the joined cabinet is larger than a cabinet can be".to_string();
    let mut files = Vec::new();
    for f in &c.files {
        let Place::In(i) = f.place else {
            return Err("a file runs on past the last cabinet".into());
        };
        files.extend_from_slice(&f.size.to_le_bytes());
        files.extend_from_slice(&f.offset.to_le_bytes());
        files.extend_from_slice(&u16::try_from(i).map_err(|_| too_big())?.to_le_bytes());
        for v in [f.date, f.time, f.attribs] {
            files.extend_from_slice(&v.to_le_bytes());
        }
        files.extend_from_slice(&f.name);
        files.push(0);
    }
    let coff_files = 36 + 8 * c.folders.len();
    let data_at = coff_files + files.len();
    let mut records = Vec::new();
    let mut data = Vec::new();
    for fo in &c.folders {
        records.extend_from_slice(
            &u32::try_from(data_at + data.len())
                .map_err(|_| too_big())?
                .to_le_bytes(),
        );
        records.extend_from_slice(
            &u16::try_from(fo.blocks.len())
                .map_err(|_| too_big())?
                .to_le_bytes(),
        );
        records.extend_from_slice(&fo.kind.to_le_bytes());
        for b in &fo.blocks {
            // No checksum: zero says there is none.
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(
                &u16::try_from(b.payload.len())
                    .map_err(|_| too_big())?
                    .to_le_bytes(),
            );
            data.extend_from_slice(&b.uncompressed.to_le_bytes());
            data.extend_from_slice(&b.payload);
        }
    }
    let total = u32::try_from(data_at + data.len()).map_err(|_| too_big())?;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(b"MSCF");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(coff_files)
            .map_err(|_| too_big())?
            .to_le_bytes(),
    );
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3, 1]);
    out.extend_from_slice(
        &u16::try_from(c.folders.len())
            .map_err(|_| too_big())?
            .to_le_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(c.files.len())
            .map_err(|_| too_big())?
            .to_le_bytes(),
    );
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&c.links.set_id.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend(records);
    out.extend(files);
    out.extend(data);
    Ok(out)
}
