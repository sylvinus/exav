//! InstallShield InstallScript cabinets (`ISc(`), InstallShield 4 and later.
//!
//! The layout is read as the `unshield` C library reads it (David Eriksson
//! and contributors, MIT; attributed in `NOTICE`). The format has no other
//! public description.
//!
//! ```text
//! common header   "ISc(", version, volume info, descriptor offset and size
//! volume header   where this cabinet's file data starts, its first and last
//!                 file (40 bytes up to InstallShield 5, 64 after)
//! descriptor      the file table: directory names, then the files (offsets
//!                 to records up to version 5, an array of 0x57-byte records
//!                 after), names in the code page or, from version 17, UTF-16
//! file data       a member stored, or deflated in chunks: a u16 length, then
//!                 that many bytes of raw deflate, each chunk on its own.
//!                 In a cabinet of InstallShield 4 or older (`old_compression`)
//!                 the chunks have no length and each ends with
//!                 `00 00 ff ff`, the empty block of a flush
//! ```
//!
//! A set is a header (`data1.hdr`, or the start of `data1.cab`) and the data
//! cabinets `data1.cab`, `data2.cab`, ... A cabinet that holds its header
//! and its files is read here, each file streamed from where it lies. A file
//! the header places in another cabinet of the set, or split across two, is
//! reported, as is a data cabinet whose header is another file: no file of
//! one can be found without it. A file may be obfuscated: each byte of its
//! stored form XORed and rotated, then shifted by its position.
//!
//! Names come out as `directory/name`, with `.` and `..` dropped; they are
//! used only for reporting and `.cdb` matching.

use std::borrow::Cow;
use std::io::{self, Read};

use flate2::{Decompress, FlushDecompress, Status};

use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_range, emit_stream};
use crate::{Budget, Format, LimitHit};

const COMMON_HEADER: usize = 20;
const VOLUME_HEADER_V5: usize = 40;
const VOLUME_HEADER_V6: usize = 64;
/// A file record from version 6 on.
const RECORD_V6: usize = 0x57;
/// A file record up to version 5.
const RECORD_V5: usize = 0x3a;

const FILE_SPLIT: u16 = 1;
const FILE_OBFUSCATED: u16 = 2;
const FILE_COMPRESSED: u16 = 4;
const FILE_INVALID: u16 = 8;
const LINK_PREV: u8 = 1;

/// The most bytes of a name read.
const NAME_MAX: usize = 1024;

fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        crate::bytes::at(d, o, 2)?.try_into().ok()?,
    ))
}

fn le32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        crate::bytes::at(d, o, 4)?.try_into().ok()?,
    ))
}

fn le64(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        crate::bytes::at(d, o, 8)?.try_into().ok()?,
    ))
}

/// The major version the header's version word encodes, as unshield reads
/// it. An encoding it does not know reads as 0, laid out as version 5.
fn major_version(version: u32) -> u32 {
    match version >> 24 {
        1 => (version >> 12) & 0xf,
        2 | 4 => (version & 0xffff) / 100,
        _ => 0,
    }
}

/// Whether the files of a cabinet with this version word are compressed the
/// old way: a cabinet of InstallShield 4 or older (unshield: "generated with
/// InstallShield <= 4", extracted with its `-O`). Their chunks have no length
/// before them and end with the bytes of a flushed deflate block. A version
/// word of an encoding unknown here is read as the new way.
fn old_compression(version: u32) -> bool {
    matches!(version >> 24, 1 | 2 | 4) && major_version(version) < 5
}

/// A file record.
struct Record {
    name_offset: u32,
    directory: u16,
    flags: u16,
    expanded: u64,
    compressed: u64,
    data_offset: u64,
    /// The data cabinet holding it, numbered from 1. Up to version 5 it is
    /// the volume header's file range that says.
    volume: u16,
    link_flags: u8,
    /// The record whose data this one names, when `link_flags` has
    /// [`LINK_PREV`].
    link_previous: u32,
}

/// The header of a set: its descriptor, with the offsets it needs.
struct Header<'a> {
    data: Cow<'a, [u8]>,
    /// The file ends inside the descriptor.
    cut: bool,
    major: u32,
    /// Its files are compressed the old way ([`old_compression`]).
    old: bool,
    /// Where the file table starts, and the offsets in it count from.
    table: usize,
    directories: usize,
    files: usize,
    /// From version 6, where the file records start, from `table`.
    records: usize,
}

impl Header<'_> {
    fn unicode(&self) -> bool {
        self.major >= 17
    }

    /// The string at `off` from the file table: null-ended, in UTF-16 from
    /// version 17.
    fn string(&self, off: u32) -> Option<String> {
        let at = self.table.checked_add(off as usize)?;
        let rest = self.data.get(at..)?;
        if self.unicode() {
            let units: Vec<u16> = rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|&u| u != 0)
                .take(NAME_MAX)
                .collect();
            Some(String::from_utf16_lossy(&units))
        } else {
            let end = rest.iter().take(NAME_MAX).position(|&b| b == 0);
            let end = end.unwrap_or(rest.len().min(NAME_MAX));
            Some(String::from_utf8_lossy(&rest[..end]).into_owned())
        }
    }

    /// The `i`th entry of the file table.
    fn table_entry(&self, i: usize) -> Option<u32> {
        le32(&self.data, self.table.checked_add(i.checked_mul(4)?)?)
    }

    fn directory(&self, i: u16) -> Option<String> {
        if usize::from(i) >= self.directories {
            return None;
        }
        self.string(self.table_entry(usize::from(i))?)
    }

    fn record(&self, i: usize) -> Option<Record> {
        let d = &self.data;
        if self.major <= 5 {
            let at = self
                .table
                .checked_add(self.table_entry(self.directories.checked_add(i)?)? as usize)?;
            // The fields read; version 5 has an MD5 after them.
            let r = crate::bytes::at(d, at, RECORD_V5 - 16)?;
            Some(Record {
                name_offset: le32(r, 0)?,
                directory: le16(r, 4)?,
                flags: le16(r, 8)?,
                expanded: u64::from(le32(r, 10)?),
                compressed: u64::from(le32(r, 14)?),
                data_offset: u64::from(le32(r, 38)?),
                volume: 1,
                link_flags: 0,
                link_previous: 0,
            })
        } else {
            let at = self
                .table
                .checked_add(self.records)?
                .checked_add(i.checked_mul(RECORD_V6)?)?;
            let r = crate::bytes::at(d, at, RECORD_V6)?;
            Some(Record {
                flags: le16(r, 0)?,
                expanded: le64(r, 2)?,
                compressed: le64(r, 10)?,
                data_offset: le64(r, 18)?,
                name_offset: le32(r, 58)?,
                directory: le16(r, 62)?,
                link_previous: le32(r, 76)?,
                link_flags: r[84],
                volume: le16(r, 85)?,
            })
        }
    }

    /// The member name of record `r`, or `None` when it has none.
    fn name(&self, r: &Record) -> Option<String> {
        let file = self.string(r.name_offset)?;
        let dir = self.directory(r.directory).unwrap_or_default();
        let path: Vec<&str> = dir
            .split(['\\', '/'])
            .chain(file.split(['\\', '/']))
            .map(str::trim)
            .filter(|c| !c.is_empty() && *c != "." && *c != "..")
            .collect();
        let path = path.join("/");
        let path: String = path.chars().filter(|c| !c.is_control()).collect();
        (!path.is_empty()).then_some(path)
    }
}

/// The common header: version, descriptor offset and size.
fn common(src: &dyn ByteSource) -> Option<(u32, u32, u32)> {
    let h = src.window(0, COMMON_HEADER);
    if h.len() < COMMON_HEADER || !super::sniff::is(&h, Format::IshieldCab) {
        return None;
    }
    Some((le32(&h, 4)?, le32(&h, 12)?, le32(&h, 16)?))
}

/// The header in `src`, held up to the end of its descriptor. `Ok(None)`
/// when `src` has no descriptor, or not one that can be read.
fn header(src: &dyn ByteSource, max: u64) -> Result<Option<Header<'_>>, LimitHit> {
    let Some((version, offset, size)) = common(src) else {
        return Ok(None);
    };
    if size == 0 {
        return Ok(None);
    }
    // The size the common header gives ends at the file table in some cabinets
    // (version 4, as unshield reads one), where the table and the records
    // follow it: they are part of the header.
    let table_end = {
        let d = src.window(offset as usize, 0x18);
        match (le32(&d, 0x0c), le32(&d, 0x14)) {
            (Some(at), Some(len)) => u64::from(offset) + u64::from(at) + u64::from(len),
            _ => 0,
        }
    };
    let end = (u64::from(offset) + u64::from(size)).max(table_end);
    if end > max {
        return Err(LimitHit::new(format!(
            "InstallShield cabinet header is {end} bytes, over the {max}-byte \
             buffer limit (--max-object-bytes): its members were not scanned"
        )));
    }
    let data = src.window(0, usize::try_from(end).unwrap_or(usize::MAX));
    let d = offset as usize;
    let field = |o: usize| le32(&data, d.checked_add(o)?);
    let (Some(table), Some(directories), Some(files), Some(records)) =
        (field(0x0c), field(0x1c), field(0x28), field(0x2c))
    else {
        return Ok(None);
    };
    let Some(table) = d.checked_add(table as usize) else {
        return Ok(None);
    };
    Ok(Some(Header {
        cut: end > src.len() as u64,
        major: major_version(version),
        old: old_compression(version),
        table,
        directories: directories as usize,
        files: files as usize,
        records: records as usize,
        data,
    }))
}

/// What the volume header of a data cabinet says: where its data starts and
/// its first and last file.
struct Volume {
    data_offset: u64,
    first: u32,
    last: u32,
    /// The stored sizes of the parts of its first and last file it holds.
    first_size: u64,
    last_size: u64,
}

impl Volume {
    /// Up to version 5 a file split across two cabinets has no flag: the
    /// part of it a cabinet holds is smaller than the file.
    fn splits(&self, i: usize, files: usize, r: &Record) -> bool {
        let Ok(i) = u32::try_from(i) else {
            return false;
        };
        (i == self.last && (i as usize).saturating_add(1) < files && self.last_size != r.compressed)
            || (i == self.first && i > 0 && self.first_size != r.compressed)
    }
}

fn volume(src: &dyn ByteSource, major: u32) -> Option<Volume> {
    let v6 = major > 5;
    let len = if v6 {
        VOLUME_HEADER_V6
    } else {
        VOLUME_HEADER_V5
    };
    let v = src.window(COMMON_HEADER, len);
    if v.len() < len {
        return None;
    }
    let wide = |o: usize| Some(u64::from(le32(&v, o)?) | u64::from(le32(&v, o + 4)?) << 32);
    let (data_offset, first_size, last_size) = if v6 {
        (wide(0)?, wide(32)?, wide(56)?)
    } else {
        (
            u64::from(le32(&v, 0)?),
            u64::from(le32(&v, 24)?),
            u64::from(le32(&v, 36)?),
        )
    };
    Some(Volume {
        data_offset,
        first: le32(&v, 8)?,
        last: le32(&v, 12)?,
        first_size,
        last_size,
    })
}

/// Undo the obfuscation of the bytes at position `pos` on of a file's stored
/// form.
fn deobfuscate(buf: &mut [u8], pos: u64) {
    for (i, b) in buf.iter_mut().enumerate() {
        let seed = pos.wrapping_add(i as u64) % 0x47;
        *b = (*b ^ 0xd5).rotate_right(2).wrapping_sub(seed as u8);
    }
}

/// A file's bytes as they are read: its stored form from where it lies,
/// deobfuscated, and inflated chunk by chunk when it is compressed.
struct FileReader<'a> {
    raw: Reader<'a>,
    /// The size of the stored form the record declares.
    declared: u64,
    /// Bytes of the stored form read so far: the obfuscation's position.
    pos: u64,
    obfuscated: bool,
    compressed: bool,
    /// The chunks are not preceded by their length but end with
    /// [`END_OF_CHUNK`] ([`old_compression`]).
    old: bool,
    /// The most an old chunk may take before its end: the buffer limit.
    cap: usize,
    /// Stored bytes read ahead, while the end of an old chunk is looked for.
    ahead: Vec<u8>,
    /// The stored form has been read to its end.
    eof: bool,
    chunk: Vec<u8>,
    /// How much of `chunk` the inflater has taken.
    taken: usize,
    inflater: Option<Decompress>,
}

/// What ends a chunk of the old compression: the empty stored block a flush
/// of the deflater writes.
const END_OF_CHUNK: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// How much of the stored form is read at a time to look for the end of an
/// old chunk.
const READ_AHEAD: usize = 64 * 1024;

impl<'a> FileReader<'a> {
    fn new(src: &'a dyn ByteSource, r: &Record, old: bool, cap: u64) -> Self {
        let size = if r.flags & FILE_COMPRESSED != 0 {
            r.compressed
        } else {
            r.expanded
        };
        let from = usize::try_from(r.data_offset).unwrap_or(usize::MAX);
        let to = usize::try_from(r.data_offset.saturating_add(size)).unwrap_or(usize::MAX);
        FileReader {
            raw: Reader::range(src, from, to),
            declared: size,
            pos: 0,
            obfuscated: r.flags & FILE_OBFUSCATED != 0,
            compressed: r.flags & FILE_COMPRESSED != 0,
            old,
            cap: usize::try_from(cap).unwrap_or(usize::MAX),
            ahead: Vec::new(),
            eof: false,
            chunk: Vec::new(),
            taken: 0,
            inflater: None,
        }
    }

    /// Up to `buf.len()` bytes of the stored form. A cabinet that ends before
    /// the stored form does is an error: the member was not read in full.
    fn raw(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = crate::read_full(&mut self.raw, buf).map_err(|e| io::Error::other(e.reason))?;
        if n == 0 && !buf.is_empty() && self.pos < self.declared {
            return Err(io::Error::other(
                "InstallShield cabinet member cut short by the end of the cabinet",
            ));
        }
        if self.obfuscated {
            deobfuscate(&mut buf[..n], self.pos);
        }
        self.pos += n as u64;
        Ok(n)
    }

    /// Read ahead until `ahead` holds `n` bytes, or the stored form ends.
    fn fill(&mut self, n: usize) -> io::Result<()> {
        while self.ahead.len() < n && !self.eof {
            let at = self.ahead.len();
            self.ahead.resize(at + READ_AHEAD, 0);
            let mut ahead = std::mem::take(&mut self.ahead);
            let got = self.raw(&mut ahead[at..]);
            self.ahead = ahead;
            let got = got?;
            self.ahead.truncate(at + got);
            self.eof = got == 0;
        }
        Ok(())
    }

    /// The next chunk of the old compression, or `false` at the end of the
    /// file: the stored bytes up to the next [`END_OF_CHUNK`]. The first bit
    /// of a deflate block that follows a flush is 0, so a marker followed by a
    /// byte with bit 0 set is data of the chunk, not its end.
    fn next_chunk_old(&mut self) -> io::Result<bool> {
        let mut from = 0;
        loop {
            let found = memchr::memmem::find(&self.ahead[from..], &END_OF_CHUNK).map(|i| i + from);
            let Some(end) = found else {
                if self.ahead.len() > self.cap {
                    return Err(io::Error::other(format!(
                        "InstallShield cabinet: a chunk over the {}-byte buffer limit \
                         (--max-object-bytes)",
                        self.cap
                    )));
                }
                if self.eof {
                    if self.ahead.is_empty() {
                        return Ok(false);
                    }
                    return Err(io::Error::other(
                        "InstallShield cabinet: a chunk with no end marker",
                    ));
                }
                // The marker may start in what is held.
                from = self.ahead.len().saturating_sub(END_OF_CHUNK.len() - 1);
                self.fill(self.ahead.len() + READ_AHEAD)?;
                continue;
            };
            self.fill(end + END_OF_CHUNK.len() + 1)?;
            if self
                .ahead
                .get(end + END_OF_CHUNK.len())
                .is_some_and(|b| b & 1 == 1)
            {
                from = end + END_OF_CHUNK.len();
                continue;
            }
            self.chunk.clear();
            self.chunk.extend_from_slice(&self.ahead[..end]);
            self.ahead.drain(..end + END_OF_CHUNK.len());
            self.taken = 0;
            self.inflater = Some(Decompress::new(false));
            return Ok(true);
        }
    }

    /// The next chunk, or `false` at the end of the file.
    fn next_chunk(&mut self) -> io::Result<bool> {
        if self.old {
            return self.next_chunk_old();
        }
        let mut len = [0u8; 2];
        if self.raw(&mut len)? < 2 {
            return Ok(false);
        }
        let len = usize::from(u16::from_le_bytes(len));
        if len == 0 {
            return Err(io::Error::other(
                "InstallShield cabinet: a chunk of length 0",
            ));
        }
        self.chunk.resize(len, 0);
        let mut chunk = std::mem::take(&mut self.chunk);
        let n = self.raw(&mut chunk);
        self.chunk = chunk;
        // What the file holds of a chunk cut short.
        self.chunk.truncate(n?);
        self.taken = 0;
        self.inflater = Some(Decompress::new(false));
        Ok(true)
    }
}

impl Read for FileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.compressed {
            return self.raw(buf);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(inflater) = &mut self.inflater {
                let (inn, out) = (inflater.total_in(), inflater.total_out());
                let status = inflater
                    .decompress(&self.chunk[self.taken..], buf, FlushDecompress::None)
                    .map_err(|e| io::Error::other(format!("InstallShield cabinet chunk: {e}")))?;
                let took = (inflater.total_in() - inn) as usize;
                let gave = (inflater.total_out() - out) as usize;
                self.taken += took;
                if gave > 0 {
                    return Ok(gave);
                }
                // A chunk ends at its final block, or where its bytes run out
                // (a chunk flushed rather than finished).
                if status == Status::StreamEnd || took == 0 {
                    self.inflater = None;
                }
                continue;
            }
            if !self.next_chunk()? {
                return Ok(0);
            }
        }
    }
}

/// Walk an InstallShield cabinet: each file the header lists, streamed from
/// this cabinet when it holds it, reported when another cabinet of the set
/// does.
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    if common(src).is_none() {
        return Ok(None);
    }
    let Some(h) = header(src, budget.limits().max_buffer_bytes)? else {
        // A data cabinet: the file table is in the set's header.
        budget.count_entry()?;
        let meta = MemberMeta {
            name: "ishield-cab".to_string(),
            comp_size: src.len() as u64,
            unsupported: Some(
                "InstallShield data cabinet whose file table is in the header \
                 of its set (data1.hdr), a file of its own: its members were \
                 not examined",
            ),
            ..MemberMeta::default()
        };
        return Ok(visit(&meta, None, budget));
    };
    // A header file has no data of its own: its volume header is empty, or
    // says the data starts where the file ends (the header of the 2009
    // installer's sets).
    let here =
        volume(src, h.major).filter(|v| v.data_offset != 0 && v.data_offset < src.len() as u64);
    let mut unreadable = 0u64;
    // The file table ends before the files the header counts.
    let mut short = false;
    for i in 0..h.files {
        if h.major <= 5 && h.table_entry(h.directories.saturating_add(i)).is_none() {
            short = true;
            break;
        }
        let Some(r) = h.record(i) else {
            if h.major > 5 {
                short = true;
                break;
            }
            // Up to version 5 the table points at each record: one that
            // points past the header is a file the walk cannot find.
            unreadable += 1;
            continue;
        };
        // An unused record.
        if r.flags & FILE_INVALID != 0 || r.data_offset == 0 || r.name_offset == 0 {
            continue;
        }
        let name = h.name(&r).unwrap_or_else(|| format!("<file-{i}>"));
        // A record that names another record's data has that record's bytes.
        let r = if r.link_flags & LINK_PREV != 0 {
            match follow(&h, &r) {
                Link::Skip => continue,
                Link::Data(target) => target,
                Link::Broken => {
                    budget.count_entry()?;
                    let meta = MemberMeta {
                        name,
                        size: Some(r.expanded),
                        unsupported: Some(
                            "InstallShield cabinet file whose link to another \
                             record's data cannot be followed: not examined",
                        ),
                        ..MemberMeta::default()
                    };
                    if let Some(t) = visit(&meta, None, budget) {
                        return Ok(Some(t));
                    }
                    continue;
                }
            }
        } else {
            r
        };
        budget.count_entry()?;
        let mut meta = MemberMeta {
            name,
            comp_size: if r.flags & FILE_COMPRESSED != 0 {
                r.compressed
            } else {
                r.expanded
            },
            size: Some(r.expanded),
            ..MemberMeta::default()
        };
        let in_this = here.as_ref().is_some_and(|v| {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            r.volume == 1 && (h.major > 5 || (v.first..=v.last).contains(&index))
        });
        let split = r.flags & FILE_SPLIT != 0
            || (h.major <= 5 && here.as_ref().is_some_and(|v| v.splits(i, h.files, &r)));
        let stop = if !in_this {
            meta.unsupported = Some(
                "InstallShield cabinet file stored in another cabinet of its \
                 set (data1.cab, data2.cab...): not examined",
            );
            visit(&meta, None, budget)
        } else if split {
            meta.unsupported = Some(
                "InstallShield cabinet file split across two cabinets of its \
                 set: not examined",
            );
            visit(&meta, None, budget)
        } else if r.flags & (FILE_COMPRESSED | FILE_OBFUSCATED) == 0 {
            // Stored as it is: a range of the cabinet.
            let mut reader = FileReader::new(src, &r, h.old, budget.limits().max_buffer_bytes);
            // The declared length: one past the end of the cabinet is reported.
            emit_range(
                &mut meta,
                (r.data_offset, r.expanded),
                &mut reader,
                budget,
                visit,
            )?
        } else {
            let mut reader = FileReader::new(src, &r, h.old, budget.limits().max_buffer_bytes);
            emit_stream(&meta, &mut reader, budget, visit)?
        };
        if let Some(t) = stop {
            return Ok(Some(t));
        }
    }
    // A descriptor the file ends in has its tail absent, and the data lies
    // past it; a whole one that holds fewer records than the header counts is
    // damaged, and the files it counts were not found.
    if unreadable > 0 || (short && !h.cut) {
        budget.count_entry()?;
        let meta = MemberMeta {
            name: "<ishield-cab-records>".to_string(),
            unsupported: Some(
                "InstallShield cabinet file records that are not in its header: \
                 those files were not examined",
            ),
            ..MemberMeta::default()
        };
        return Ok(visit(&meta, None, budget));
    }
    Ok(None)
}

/// How many records a chain of links is followed through. unshield follows
/// them by recursion.
const LINK_DEPTH: usize = 64;

/// What a record that names another record's data comes to.
enum Link {
    /// The data is listed under another record, or there is none.
    Skip,
    /// The data of this record, which is not listed on its own.
    Data(Record),
    /// The chain loops, is too long or leaves the file table.
    Broken,
}

/// Follow `r`'s link to the record that holds the data. The data of a record
/// flagged unused or without a name is returned too: a link names it, and
/// bytes a link can reach are scanned whatever the record says of itself.
fn follow(h: &Header, r: &Record) -> Link {
    let mut next = r.link_previous;
    for _ in 0..LINK_DEPTH {
        let Some(t) = usize::try_from(next)
            .ok()
            .filter(|&n| n < h.files)
            .and_then(|n| h.record(n))
        else {
            return Link::Broken;
        };
        if t.link_flags & LINK_PREV != 0 {
            next = t.link_previous;
            continue;
        }
        if t.data_offset == 0 {
            return Link::Skip;
        }
        // A record in use is walked on its own, with the same bytes.
        let listed = t.flags & FILE_INVALID == 0 && t.name_offset != 0;
        return if listed { Link::Skip } else { Link::Data(t) };
    }
    Link::Broken
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Limits, Member};
    use std::io::Write;

    /// One file of a cabinet the tests build.
    pub(crate) struct Spec<'a> {
        pub dir: &'a str,
        pub name: &'a str,
        pub data: &'a [u8],
        pub compressed: bool,
        pub obfuscated: bool,
        /// The cabinet it is in, from 1.
        pub volume: u16,
    }

    pub(crate) fn file<'a>(dir: &'a str, name: &'a str, data: &'a [u8]) -> Spec<'a> {
        Spec {
            dir,
            name,
            data,
            compressed: false,
            obfuscated: false,
            volume: 1,
        }
    }

    fn obfuscate(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            let seed = (i % 0x47) as u8;
            *b = b.wrapping_add(seed).rotate_left(2) ^ 0xd5;
        }
    }

    /// Raw deflate in chunks of `chunk` input bytes, each finished on its
    /// own, as InstallShield writes them.
    fn chunks(data: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in data.chunks(chunk.max(1)) {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            e.write_all(part).unwrap();
            let z = e.finish().unwrap();
            out.extend_from_slice(&(z.len() as u16).to_le_bytes());
            out.extend_from_slice(&z);
        }
        out
    }

    /// Raw deflate in chunks of `chunk` input bytes as InstallShield 4 writes
    /// them: each flushed, not finished, so that it ends with the marker, and
    /// with no length before it. `stored` writes the chunks without
    /// compressing them, so that their bytes are the data's own.
    pub(crate) fn chunks_old(data: &[u8], chunk: usize, stored: bool) -> Vec<u8> {
        let level = if stored {
            flate2::Compression::none()
        } else {
            flate2::Compression::best()
        };
        let mut out = Vec::new();
        for part in data.chunks(chunk.max(1)) {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), level);
            e.write_all(part).unwrap();
            e.flush().unwrap();
            out.extend_from_slice(e.get_ref());
        }
        out
    }

    fn put(out: &mut [u8], at: usize, v: &[u8]) {
        out[at..at + v.len()].copy_from_slice(v);
    }

    /// A cabinet holding its header and the files, laid out as unshield
    /// reads one: `major` 5, 6 or 17 and later (names in UTF-16).
    pub(crate) fn build(major: u32, files: &[Spec]) -> Vec<u8> {
        let version = match major {
            4 => 0x0100_0004,
            5 => 0x0100_5000,
            6..=15 => 0x0100_0000 | (major << 12),
            _ => 0x0400_0000 | (major * 100),
        };
        let d = 0x200usize;
        let table_off = 0x200usize; // from d
        let t = d + table_off;
        let mut dirs: Vec<&str> = Vec::new();
        for f in files {
            if !dirs.contains(&f.dir) {
                dirs.push(f.dir);
            }
        }
        let n = files.len();
        let mut hdr = vec![0u8; t];
        let entries = dirs.len() + if major <= 5 { n } else { 0 };
        hdr.resize(t + entries * 4, 0);
        let string = |hdr: &mut Vec<u8>, s: &str| -> u32 {
            let off = (hdr.len() - t) as u32;
            if major >= 17 {
                for u in s.encode_utf16() {
                    hdr.extend_from_slice(&u.to_le_bytes());
                }
                hdr.extend_from_slice(&[0, 0]);
            } else {
                hdr.extend_from_slice(s.as_bytes());
                hdr.push(0);
            }
            off
        };
        for (i, dir) in dirs.iter().enumerate() {
            let off = string(&mut hdr, dir);
            put(&mut hdr, t + i * 4, &off.to_le_bytes());
        }
        let names: Vec<u32> = files.iter().map(|f| string(&mut hdr, f.name)).collect();
        let records = hdr.len() - t;
        let rec_len = if major <= 5 { RECORD_V5 } else { RECORD_V6 };
        let rec_start = hdr.len();
        hdr.resize(rec_start + n * rec_len, 0);
        let header_end = hdr.len();
        // The data, after the header.
        let mut data = Vec::new();
        let mut placed = Vec::new();
        for f in files {
            let mut stored = if f.compressed && major == 4 {
                chunks_old(f.data, 1000, false)
            } else if f.compressed {
                chunks(f.data, 1000)
            } else {
                f.data.to_vec()
            };
            if f.obfuscated {
                obfuscate(&mut stored);
            }
            placed.push(((header_end + data.len()) as u64, stored.len() as u64));
            data.extend_from_slice(&stored);
        }
        for (i, f) in files.iter().enumerate() {
            let at = rec_start + i * rec_len;
            let dir = dirs.iter().position(|x| *x == f.dir).unwrap() as u16;
            let flags = u16::from(f.compressed) * FILE_COMPRESSED
                + u16::from(f.obfuscated) * FILE_OBFUSCATED;
            let (off, stored) = placed[i];
            let r = &mut hdr[at..at + rec_len];
            if major <= 5 {
                put(r, 0, &names[i].to_le_bytes());
                put(r, 4, &dir.to_le_bytes());
                put(r, 8, &flags.to_le_bytes());
                put(r, 10, &(f.data.len() as u32).to_le_bytes());
                put(r, 14, &(stored as u32).to_le_bytes());
                put(r, 38, &(off as u32).to_le_bytes());
                put(
                    &mut hdr,
                    t + (dirs.len() + i) * 4,
                    &((at - t) as u32).to_le_bytes(),
                );
            } else {
                put(r, 0, &flags.to_le_bytes());
                put(r, 2, &(f.data.len() as u64).to_le_bytes());
                put(r, 10, &stored.to_le_bytes());
                put(r, 18, &off.to_le_bytes());
                put(r, 58, &names[i].to_le_bytes());
                put(r, 62, &dir.to_le_bytes());
                put(r, 85, &f.volume.to_le_bytes());
            }
        }
        put(&mut hdr, 0, b"ISc(");
        put(&mut hdr, 4, &version.to_le_bytes());
        put(&mut hdr, 12, &(d as u32).to_le_bytes());
        put(&mut hdr, 16, &((header_end - d) as u32).to_le_bytes());
        // The volume header: data start, first and last file.
        put(&mut hdr, 20, &(header_end as u32).to_le_bytes());
        put(&mut hdr, 28, &0u32.to_le_bytes());
        put(&mut hdr, 32, &(n.saturating_sub(1) as u32).to_le_bytes());
        put(&mut hdr, d + 0x0c, &(table_off as u32).to_le_bytes());
        put(&mut hdr, d + 0x1c, &(dirs.len() as u32).to_le_bytes());
        put(&mut hdr, d + 0x28, &(n as u32).to_le_bytes());
        put(&mut hdr, d + 0x2c, &(records as u32).to_le_bytes());
        hdr.extend_from_slice(&data);
        hdr
    }

    /// The same set as its header file alone: the descriptor, no data.
    pub(crate) fn header_only(cab: &[u8]) -> Vec<u8> {
        let end = 0x200 + le32(cab, 16).unwrap() as usize;
        let mut h = cab[..end].to_vec();
        h[20..20 + VOLUME_HEADER_V6].fill(0);
        h
    }

    type Seen = Vec<(String, Vec<u8>, Option<&'static str>)>;

    fn walked(data: &[u8], limits: Limits) -> (Seen, Result<(), LimitHit>) {
        let mut budget = Budget::new(limits);
        let mut seen = Vec::new();
        let end = walk(&data, &mut budget, &mut |meta, content, _| {
            let mut bytes = Vec::new();
            if let Some(Member::Stream(r)) = content {
                let _ = r.read_to_end(&mut bytes);
            }
            seen.push((meta.name.clone(), bytes, meta.unsupported));
            None::<()>
        });
        (seen, end.map(|_| ()))
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn every_version_layout_gives_its_files() {
        let big = payload(5000);
        for major in [4, 5, 6, 12, 17, 24] {
            let files = [
                file("", "setup.ini", b"[Startup]"),
                Spec {
                    compressed: true,
                    ..file("Program Files\\App", "app.exe", &big)
                },
                Spec {
                    compressed: true,
                    obfuscated: true,
                    ..file("Program Files\\App", "data.bin", &big[..3000])
                },
                Spec {
                    obfuscated: true,
                    ..file("Common", "plain.txt", b"stored and obfuscated")
                },
            ];
            let cab = build(major, &files);
            let (seen, end) = walked(&cab, Limits::default());
            end.unwrap();
            let want: Seen = vec![
                ("setup.ini".into(), b"[Startup]".to_vec(), None),
                ("Program Files/App/app.exe".into(), big.clone(), None),
                (
                    "Program Files/App/data.bin".into(),
                    big[..3000].to_vec(),
                    None,
                ),
                (
                    "Common/plain.txt".into(),
                    b"stored and obfuscated".to_vec(),
                    None,
                ),
            ];
            assert_eq!(seen, want, "version {major}");
        }
    }

    /// From a live installer (InstallShield 2009, version 4): the size in the
    /// common header ends at the file table, which and the records follow, and
    /// the size of the table is a field of the descriptor. The files are
    /// those unshield lists.
    #[test]
    fn a_header_whose_size_ends_at_the_file_table_is_read_to_the_end_of_the_table() {
        let text = payload(300);
        let files = [
            file("", "setup.ini", b"[Startup]"),
            file("Common", "plain.txt", &text),
        ];
        let cab = build(5, &files);
        let (want, _) = walked(&cab, Limits::default());
        assert_eq!(want.len(), 2);
        assert!(want.iter().all(|(_, _, why)| why.is_none()));
        let d = 0x200;
        let table = le32(&cab, d + 0x0c).unwrap() as usize;
        let header_end = d + le32(&cab, 16).unwrap() as usize;
        let mut short = cab.clone();
        put(
            &mut short,
            d + 0x14,
            &((header_end - d - table) as u32).to_le_bytes(),
        );
        put(&mut short, 16, &((table + 8) as u32).to_le_bytes());
        let (seen, end) = walked(&short, Limits::default());
        end.unwrap();
        assert_eq!(seen, want);
    }

    #[test]
    fn a_cabinet_on_disk_is_read_where_it_lies() {
        let big = payload(20_000);
        let files = [
            Spec {
                compressed: true,
                ..file("", "a.bin", &big)
            },
            file("", "b.bin", &big[..7000]),
        ];
        let cab = build(6, &files);
        assert_eq!(crate::detect(&cab), Some(Format::IshieldCab));
        let (want, _) = walked(&cab, Limits::default());
        let cached =
            crate::source::BlockCache::with_sizes(io::Cursor::new(cab.clone()), 512, 4096).unwrap();
        let mut budget = Budget::new(Limits::default());
        let mut seen = Vec::new();
        crate::walk(
            Format::IshieldCab,
            &cached,
            &mut budget,
            &mut |meta, content, _| {
                let mut bytes = Vec::new();
                if let Some(Member::Stream(r)) = content {
                    r.read_to_end(&mut bytes).unwrap();
                }
                seen.push((meta.name.clone(), bytes, meta.unsupported));
                None::<()>
            },
        )
        .unwrap();
        assert_eq!(seen, want);
        assert_eq!(seen[0].1, big);
        if !cfg!(feature = "zip") {
            return;
        }
        // Inside a ZIP, the member is typed as a cabinet.
        let mut z = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        z.start_file("data1.cab", zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(&cab).unwrap();
        let z = z.finish().unwrap().into_inner();
        let mut inner = None;
        crate::walk(
            Format::Zip,
            &z,
            &mut Budget::new(Limits::default()),
            &mut |_, c, b| {
                let (bytes, _) = c?.into_bytes(&Default::default(), b).ok()?;
                inner = Some(bytes);
                None::<()>
            },
        )
        .unwrap();
        assert_eq!(crate::detect(&inner.unwrap()), Some(Format::IshieldCab));
    }

    #[test]
    fn the_version_word_is_read_as_unshield_reads_it() {
        assert_eq!(major_version(0x0100_5000), 5);
        assert_eq!(major_version(0x0100_6000), 6);
        assert_eq!(major_version(0x0200_0000 | 1200), 12);
        assert_eq!(major_version(0x0400_0000 | 2400), 24);
        assert_eq!(major_version(0x0700_0000), 0);
    }

    #[test]
    fn a_name_cannot_climb_out() {
        let cab = build(6, &[file("..\\..\\Windows", "..\\evil.dll", b"x")]);
        let (seen, _) = walked(&cab, Limits::default());
        assert_eq!(seen[0].0, "Windows/evil.dll");
    }

    #[test]
    fn a_file_in_another_cabinet_is_reported() {
        let cab = build(
            6,
            &[
                file("", "here.txt", b"here"),
                Spec {
                    volume: 2,
                    ..file("", "there.txt", b"there")
                },
            ],
        );
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen[0], ("here.txt".into(), b"here".to_vec(), None));
        assert_eq!(seen[1].0, "there.txt");
        assert!(seen[1].2.is_some() && seen[1].1.is_empty());
    }

    #[test]
    fn a_file_split_across_cabinets_is_reported() {
        // Version 5: the cabinet ends with part of its last file.
        let mut cab = build(5, &[file("", "a.txt", b"aaa"), file("", "b.txt", b"bbb")]);
        put(&mut cab, 32, &0u32.to_le_bytes());
        put(&mut cab, 20 + 36, &1u32.to_le_bytes());
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|(_, b, u)| b.is_empty() && u.is_some()));
        // Later versions flag it.
        let mut cab = build(6, &[file("", "a.txt", b"aaa")]);
        let rec = 0x400 + le32(&cab, 0x200 + 0x2c).unwrap() as usize;
        assert_eq!(le16(&cab, rec), Some(0));
        put(&mut cab, rec, &FILE_SPLIT.to_le_bytes());
        let (seen, _) = walked(&cab, Limits::default());
        assert!(seen[0].1.is_empty() && seen[0].2.is_some());
    }

    /// Where record `i` of a version 6 cabinet `build` made is.
    fn record_at(cab: &[u8], i: usize) -> usize {
        0x400 + le32(cab, 0x200 + 0x2c).unwrap() as usize + i * RECORD_V6
    }

    /// Makes record `i` a link to record `to`.
    fn link(cab: &mut [u8], i: usize, to: u32) {
        let at = record_at(cab, i);
        put(cab, at + 76, &to.to_le_bytes());
        cab[at + 84] = LINK_PREV;
    }

    #[test]
    fn a_link_reaches_the_data_of_a_record_marked_unused() {
        let big = payload(5000);
        let mut cab = build(
            6,
            &[
                Spec {
                    compressed: true,
                    obfuscated: true,
                    ..file("", "unused.bin", &big)
                },
                file("", "alias.txt", b"alias"),
            ],
        );
        link(&mut cab, 1, 0);
        // Record 0 is in use, so its data is walked once, under its own name.
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].0 == "unused.bin" && seen[0].1 == big && seen[0].2.is_none());
        // Marked unused, or without a name, its data is still what the link
        // names.
        let at = record_at(&cab, 0);
        let mut unused = cab.clone();
        put(
            &mut unused,
            at,
            &(FILE_COMPRESSED | FILE_OBFUSCATED | FILE_INVALID).to_le_bytes(),
        );
        let mut unnamed = cab.clone();
        put(&mut unnamed, at + 58, &0u32.to_le_bytes());
        for (what, cab) in [("flags", unused), ("name", unnamed)] {
            let (seen, end) = walked(&cab, Limits::default());
            end.unwrap();
            assert_eq!(seen.len(), 1, "{what}");
            assert!(seen[0].0 == "alias.txt" && seen[0].1 == big, "{what}");
        }
    }

    #[test]
    fn a_link_that_cannot_be_followed_is_reported() {
        let base = build(6, &[file("", "a.txt", b"aaa"), file("", "b.txt", b"bbb")]);
        // To a record that is not there, to itself, and in a loop.
        for (a, b) in [(7, 8), (0, 1), (1, 0)] {
            let mut cab = base.clone();
            link(&mut cab, 0, a);
            link(&mut cab, 1, b);
            let (seen, end) = walked(&cab, Limits::default());
            end.unwrap();
            assert_eq!(seen.len(), 2, "{a} {b}");
            assert!(seen.iter().all(|(_, d, u)| d.is_empty() && u.is_some()));
        }
    }

    #[test]
    fn a_file_table_shorter_than_its_count_is_reported_unless_the_file_is_cut() {
        let mut cab = build(6, &[file("", "a.txt", b"a"), file("", "b.txt", b"b")]);
        put(&mut cab, 0x200 + 0x28, &9u32.to_le_bytes());
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2].0, "<ishield-cab-records>");
        assert!(seen[2].2.is_some());
        // The file ends inside the descriptor: the rest is absent.
        let cab = build(6, &[file("", "a.txt", b"a"), file("", "b.txt", b"b")]);
        let cut = &cab[..record_at(&cab, 1) + 10];
        let (seen, end) = walked(cut, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "a.txt");
    }

    #[test]
    fn a_record_the_table_places_past_the_header_is_reported() {
        let mut cab = build(5, &[file("", "a.txt", b"aaa"), file("", "b.txt", b"bbb")]);
        // The table: one directory, then the two records' offsets.
        put(&mut cab, 0x400 + 8, &0xffff_0000u32.to_le_bytes());
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], ("a.txt".into(), b"aaa".to_vec(), None));
        assert!(seen[1].2.is_some());
    }

    #[test]
    fn a_header_file_lists_its_files_as_not_examined() {
        let cab = build(6, &[file("", "a.txt", b"aaa"), file("", "b.txt", b"bbb")]);
        let (seen, end) = walked(&header_only(&cab), Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|(_, b, u)| b.is_empty() && u.is_some()));
    }

    /// From the 2009 installer: a header file whose volume header says the
    /// data starts where the file ends, with records that give offsets and
    /// sizes of files in the data cabinet. Read as its own data they ended
    /// "deflate decompression error" or "cut short"; they are files in another
    /// cabinet.
    #[test]
    fn a_header_whose_data_starts_at_its_end_lists_its_files_as_not_examined() {
        let big = payload(5000);
        let files = [
            Spec {
                compressed: true,
                ..file("", "a.bin", &big)
            },
            Spec {
                compressed: true,
                ..file("", "b.bin", &big[..3000])
            },
        ];
        for major in [6, 15] {
            let cab = build(major, &files);
            // The header alone, with a volume header whose data offset is the
            // end of the file; the records still give the offsets of the data.
            let mut hdr = header_only(&cab);
            let len = hdr.len() as u32;
            put(&mut hdr, 20, &len.to_le_bytes());
            let (seen, end) = walked(&hdr, Limits::default());
            end.unwrap();
            assert_eq!(seen.len(), 2, "version {major}");
            assert!(
                seen.iter().all(|(_, b, u)| b.is_empty() && u.is_some()),
                "version {major}: {seen:?}"
            );
        }
    }

    #[test]
    fn a_data_cabinet_without_its_header_is_reported() {
        let mut cab = build(6, &[file("", "a.txt", b"aaa")]);
        cab[16..20].fill(0);
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].2.is_some());
    }

    #[test]
    fn a_cabinet_cut_short_gives_what_it_holds() {
        let big = payload(5000);
        let cab = build(
            6,
            &[Spec {
                compressed: true,
                ..file("", "big.bin", &big)
            }],
        );
        // Cut inside the data: what the chunks there inflate to, and the read
        // fails at the cut rather than ending as if the member were whole.
        let cut = &cab[..cab.len() - 100];
        let (seen, _) = walked(cut, Limits::default());
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].1.is_empty() && big.starts_with(&seen[0].1));
        let stored = build(6, &[file("", "s.bin", &big)]);
        for (c, is_stored) in [(cut, false), (&stored[..stored.len() - 100], true)] {
            let mut failed = false;
            let mut range = None;
            walk(
                &c,
                &mut Budget::new(Limits::default()),
                &mut |meta, content, _| {
                    range = meta.range;
                    if let Some(Member::Stream(r)) = content {
                        failed = io::copy(r, &mut io::sink()).is_err();
                    }
                    None::<()>
                },
            )
            .unwrap();
            assert!(failed);
            // A stored member names the length its record declares, so that
            // the scanner can tell the cabinet ends before it does.
            assert_eq!(
                range.map(|(_, len)| len),
                is_stored.then_some(big.len() as u64)
            );
        }
        // Cut inside the file records: the records that are there.
        let (seen, end) = walked(&cab[..0x400 + 4], Limits::default());
        end.unwrap();
        assert!(seen.is_empty());
    }

    #[test]
    fn a_damaged_chunk_is_an_error_not_an_end() {
        let big = payload(5000);
        let mut cab = build(
            6,
            &[Spec {
                compressed: true,
                ..file("", "big.bin", &big)
            }],
        );
        // The second chunk's first block, of the reserved type.
        let data = 0x200 + le32(&cab, 16).unwrap() as usize;
        let second = data + 2 + usize::from(le16(&cab, data).unwrap()) + 2;
        cab[second] = 0x07;
        let mut budget = Budget::new(Limits::default());
        let mut got = None;
        walk(&cab, &mut budget, &mut |_, content, _| {
            if let Some(Member::Stream(r)) = content {
                let mut out = Vec::new();
                got = Some((r.read_to_end(&mut out).is_err(), out));
            }
            None::<()>
        })
        .unwrap();
        let (failed, out) = got.unwrap();
        assert!(failed);
        // The first chunk's 1000 bytes came out before it.
        assert_eq!(out, big[..1000]);
    }

    /// The old compression is told by the version word: InstallShield 4 and
    /// older, in an encoding this reader knows. The word of a cabinet from the
    /// 2009 installer is 0x01000004; the same installer has cabinets of
    /// version 15 (0x020005dc) that are compressed the new way.
    #[test]
    fn the_old_compression_is_told_by_the_version_word() {
        for (word, old) in [
            (0x0100_0004u32, true),
            (0x0200_0190, true),
            (0x0100_5000, false),
            (0x0100_6000, false),
            (0x0200_01f4, false),
            (0x0200_05dc, false),
            (0x0400_0000 | 2400, false),
            (0x0700_0000, false),
        ] {
            assert_eq!(old_compression(word), old, "{word:#010x}");
        }
    }

    /// Chunks of the old compression are cut at the marker, one with no
    /// length before it: a chunk of stored data that holds the marker (the
    /// byte after it is odd, which a block's first bit never is) is not cut
    /// there, and the bytes come out whole.
    #[test]
    fn an_old_cabinet_is_read_chunk_by_chunk_up_to_the_marker() {
        let mut data = payload(3000);
        let at = 1500;
        data[at..at + 5].copy_from_slice(&[0x00, 0x00, 0xff, 0xff, 0x01]);
        let marker_chunk = chunks_old(&data[..2000], 2000, true);
        // The marker is in the stored bytes of the first chunk.
        assert!(
            marker_chunk
                .windows(5)
                .any(|w| w == [0x00, 0x00, 0xff, 0xff, 0x01])
        );
        // Build by hand: the cabinet's file is the stored chunk, then two more.
        let mut stored = marker_chunk;
        stored.extend_from_slice(&chunks_old(&data[2000..], 500, false));
        let mut cab = build(4, &[file("", "a.bin", &[])]);
        // Replace the file's data with `stored` and fix the sizes.
        let header_end = 0x200 + le32(&cab, 16).unwrap() as usize;
        cab.truncate(header_end);
        cab.extend_from_slice(&stored);
        let rec = 0x200 + 0x200 + le32(&cab, 0x200 + 0x2c).unwrap() as usize;
        let r = rec;
        let flags = le16(&cab, r + 8).unwrap() | FILE_COMPRESSED;
        put(&mut cab, r + 8, &flags.to_le_bytes());
        put(&mut cab, r + 10, &(data.len() as u32).to_le_bytes());
        put(&mut cab, r + 14, &(stored.len() as u32).to_le_bytes());
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, data);
        assert_eq!(seen[0].2, None);
    }

    /// A file of the old compression whose last chunk has no marker is cut
    /// short, and one whose chunk is longer than the buffer limit is refused:
    /// both are errors of the member, not ends.
    #[test]
    fn an_old_chunk_with_no_marker_or_over_the_limit_is_an_error() {
        let data = payload(5000);
        let files = [Spec {
            compressed: true,
            ..file("", "a.bin", &data)
        }];
        let cab = build(4, &files);
        let read = |cab: &[u8], limits: Limits| {
            let mut budget = Budget::new(limits);
            let mut got = None;
            walk(&cab, &mut budget, &mut |_, content, _| {
                if let Some(Member::Stream(r)) = content {
                    let mut out = Vec::new();
                    got = Some((r.read_to_end(&mut out).map_err(|e| e.to_string()), out));
                }
                None::<()>
            })
            .unwrap();
            got.unwrap()
        };
        let (ok, out) = read(&cab, Limits::default());
        ok.unwrap();
        assert_eq!(out, data);
        // The marker of the last chunk is cut off, and the sizes follow it.
        let mut cut = cab.clone();
        cut.truncate(cut.len() - 4);
        let rec = 0x200 + 0x200 + le32(&cab, 0x200 + 0x2c).unwrap() as usize;
        let stored = le32(&cab, rec + 14).unwrap() - 4;
        put(&mut cut, rec + 14, &stored.to_le_bytes());
        let (err, out) = read(&cut, Limits::default());
        let err = err.unwrap_err();
        assert!(err.contains("no end marker"), "{err}");
        // The chunks before it came out.
        assert!(!out.is_empty() && data.starts_with(&out));
        // Nothing ends a chunk within the buffer limit.
        let mut big = build(
            4,
            &[Spec {
                compressed: true,
                ..file("", "a.bin", &data)
            }],
        );
        let header_end = 0x200 + le32(&big, 16).unwrap() as usize;
        big.truncate(header_end);
        let noise: Vec<u8> = (0..20_000usize).map(|i| (i % 251) as u8 | 0x10).collect();
        big.extend_from_slice(&noise);
        put(&mut big, rec + 14, &(noise.len() as u32).to_le_bytes());
        let (err, _) = read(
            &big,
            Limits {
                max_buffer_bytes: 4096,
                ..Limits::default()
            },
        );
        let err = err.unwrap_err();
        assert!(err.contains("buffer limit"), "{err}");
    }

    #[test]
    fn a_count_past_the_records_held_is_bounded_by_them() {
        let mut cab = build(6, &[file("", "a.txt", b"a"), file("", "b.txt", b"b")]);
        put(&mut cab, 0x200 + 0x28, &u32::MAX.to_le_bytes());
        let (seen, end) = walked(&cab, Limits::default());
        end.unwrap();
        // The two records, and the report of the files that are not there.
        assert_eq!(seen.len(), 3);
        let limits = Limits {
            max_members: 1,
            ..Limits::default()
        };
        let (seen, end) = walked(&cab, limits);
        assert_eq!(seen.len(), 1);
        assert!(!end.unwrap_err().is_corrupt());
    }

    #[test]
    fn a_header_over_the_buffer_limit_is_a_limit() {
        let cab = build(6, &[file("", "a.txt", b"a")]);
        let limits = Limits {
            max_buffer_bytes: 100,
            ..Limits::default()
        };
        let (seen, end) = walked(&cab, limits);
        assert!(seen.is_empty());
        assert!(!end.unwrap_err().is_corrupt());
    }
}
