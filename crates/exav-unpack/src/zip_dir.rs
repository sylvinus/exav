//! The central directory of a ZIP, read from the end of the file: the end
//! record (APPNOTE 4.3.16), the ZIP64 end record and locator (4.3.14, 4.3.15),
//! the central headers (4.3.12) and their ZIP64 (4.5.3), NTFS (4.5.5) and
//! extended timestamp (4.5.7) extra fields, and the Info-ZIP Unicode Path
//! field.
//!
//! A file can hold several end records (in a comment, in a member, after an
//! appended archive) and offsets that point elsewhere than the directory is.
//! The choices are on [`open`], [`read`] and [`directory_shift`]. One parser:
//! it takes `&mut dyn ReadSeek`, so it is compiled once whatever reads.

use std::borrow::Cow;
use std::io::{BufReader, Read, Seek, SeekFrom};

use crate::Mtime;
use crate::formats::package::ReadSeek;
use crate::zip_end::EndRecord;

const CENTRAL_SIG: &[u8; 4] = b"PK\x01\x02";
const CENTRAL_LEN: usize = Header::LEN;
const LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";
const LOCATOR_LEN: u64 = 20;
const ZIP64_END_SIG: &[u8; 4] = b"PK\x06\x06";
const ZIP64_END_LEN: usize = 56;
/// An end record starts at most this far from the end of the file to be
/// taken: the longest comment (65535), the record (22) and 15 bytes more.
const END_REACH: u64 = 65_572;
/// Bytes read at a time when the end of the file is searched for end records,
/// from its end, after the first read of the size of a record: few, for a source
/// of the end of a file to be asked for little more of what is before it than
/// the search comes to.
const END_CHUNK: u64 = 256;

/// Why a directory could not be read.
#[derive(Debug)]
pub(crate) enum Error {
    Io(std::io::Error),
    Invalid(&'static str),
    /// The directory read as far as `count` entries that start, and then an
    /// entry did not parse (an extra field) or the last one ends past the end
    /// of the file. The fault is the directory's, so it fails every end record
    /// that points at the same place, where the end of the entries that start
    /// fails only the record that counted more.
    Directory(&'static str),
}

impl Error {
    /// Whether the source did not hold bytes it was asked for, which a source
    /// of the end of a file does not for the bytes before it. The directory
    /// cannot be told from what is held then, and no other end record is tried.
    fn is_missing(&self) -> bool {
        matches!(self, Error::Io(e) if missing(e))
    }
}

/// Whether `e` is a source saying it does not hold the bytes, as opposed to
/// the end of the file, which is an error of another kind.
fn missing(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::Other
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Invalid(why) | Error::Directory(why) => f.write_str(why),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// The fixed part of a central header (4.3.12).
pub(crate) struct Header {
    made_by: u16,
    pub(crate) flags: u16,
    pub(crate) method: u16,
    time: u16,
    date: u16,
    pub(crate) crc: u32,
    compressed: u32,
    size: u32,
    pub(crate) name_len: usize,
    pub(crate) extra_len: usize,
    pub(crate) comment_len: usize,
    external: u32,
    /// Where the local header is, from the archive's start.
    pub(crate) local: u32,
}

impl Header {
    /// Bytes of the fixed part.
    pub(crate) const LEN: usize = 46;

    /// The header at the start of `b`; `None` when it is not one or is cut.
    pub(crate) fn parse(b: &[u8]) -> Option<Header> {
        let b = b.get(..CENTRAL_LEN)?;
        if !b.starts_with(CENTRAL_SIG) {
            return None;
        }
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Some(Header {
            made_by: u16_at(4),
            flags: u16_at(8),
            method: u16_at(10),
            time: u16_at(12),
            date: u16_at(14),
            crc: u32_at(16),
            compressed: u32_at(20),
            size: u32_at(24),
            name_len: usize::from(u16_at(28)),
            extra_len: usize::from(u16_at(30)),
            comment_len: usize::from(u16_at(32)),
            external: u32_at(38),
            local: u32_at(42),
        })
    }

    /// The bytes after the fixed part: name, extra field and comment.
    pub(crate) fn variable_len(&self) -> usize {
        self.name_len + self.extra_len + self.comment_len
    }
}

/// A member of the directory.
#[derive(Clone)]
pub(crate) struct Entry {
    /// As the directory gives it, or as its Unicode Path field does when the
    /// field's checksum is that of the name.
    pub(crate) name: Box<[u8]>,
    pub(crate) flags: u16,
    pub(crate) method: u16,
    pub(crate) crc: u32,
    pub(crate) compressed: u64,
    pub(crate) size: u64,
    /// Where the local header is, from the start of the file.
    pub(crate) header: u64,
    made_by: u16,
    external: u32,
    date: u16,
    time: u16,
    /// The first time an extended timestamp or NTFS field holds.
    stamp: Option<Mtime>,
    /// The strength and real method from the first WinZip AES field (0x9901:
    /// version, "AE", strength, method) with room for them.
    pub(crate) aes: Option<(u8, u16)>,
}

/// Extra field ids whose length must be there to be read at all.
const FRAMED_IDS: [u16; 7] = [0x0001, 0x000a, 0x5455, 0x6375, 0x7075, 0x9901, 0xa11e];
/// FILETIME ticks per second, and the seconds from 1601 to 1970.
const FILETIME_TICKS: u64 = 10_000_000;
const FILETIME_EPOCH: i64 = 11_644_473_600;

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    let w = b.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_le_bytes([w[0], w[1]])))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

impl Entry {
    /// The entry of `head`, `name` and `extra`, its local header offset still
    /// counted from the archive's start.
    ///
    /// The extra field is read as a list of (id, length, data). Fewer than 4
    /// bytes left end it, unless the id is one of [`FRAMED_IDS`], whose length
    /// must be there. A field longer than what is left is an error, and so is
    /// a field of these ids that is too short: ZIP64 for the sizes the header
    /// leaves at 0xFFFFFFFF, NTFS unless exactly its one attribute of 24 bytes,
    /// extended timestamp and Unicode comment and path with less than their
    /// first bytes. A later ZIP64 field replaces the values of an earlier one.
    fn parse(head: &Header, name: &[u8], extra: &[u8]) -> Result<Entry, Error> {
        let bad = || Error::Directory("invalid extra field in the central directory");
        let mut entry = Entry {
            name: Box::default(),
            flags: head.flags,
            method: head.method,
            crc: head.crc,
            compressed: u64::from(head.compressed),
            size: u64::from(head.size),
            header: 0,
            made_by: head.made_by,
            external: head.external,
            date: head.date,
            time: head.time,
            stamp: None,
            aes: None,
        };
        let mut local = u64::from(head.local);
        let mut shown: Option<&[u8]> = None;
        let mut at = 0;
        while let Some(id) = u16_at(extra, at).map(|i| i as u16) {
            at += 2;
            let Some(len) = u16_at(extra, at) else {
                if FRAMED_IDS.contains(&id) {
                    return Err(bad());
                }
                break;
            };
            at += 2;
            // A ZIP64 field may claim more than the extra field holds.
            let Some(body) = extra
                .get(at..at + len)
                .or_else(|| (id == 0x0001).then(|| &extra[at..]))
            else {
                return Err(bad());
            };
            at += len;
            match id {
                0x0001 => {
                    let mut pos = 0;
                    let mut take = || -> Option<u64> {
                        let v = body.get(pos..pos + 8)?;
                        pos += 8;
                        Some(u64_at(v, 0))
                    };
                    if head.size == u32::MAX {
                        entry.size = take().ok_or_else(bad)?;
                    }
                    if head.compressed == u32::MAX {
                        entry.compressed = take().ok_or_else(bad)?;
                    }
                    if head.local == u32::MAX {
                        local = take().ok_or_else(bad)?;
                    }
                }
                0x000a => {
                    if body.len() != 32 || body[4..8] != [1, 0, 24, 0] {
                        return Err(bad());
                    }
                    if entry.stamp.is_none() {
                        let secs = i64::try_from(u64_at(body, 8) / FILETIME_TICKS).ok();
                        entry.stamp = secs.map(|s| Mtime::Unix(s - FILETIME_EPOCH));
                    }
                }
                0x5455 => {
                    if body.is_empty() {
                        return Err(bad());
                    }
                    if body.len() >= 5 && entry.stamp.is_none() {
                        entry.stamp = Some(Mtime::Unix(i64::from(u32_at(body, 1))));
                    }
                }
                0x6375 if body.len() < 5 => return Err(bad()),
                0x9901 => {
                    if body.len() >= 7 && entry.aes.is_none() {
                        entry.aes = Some((body[4], u16::from_le_bytes([body[5], body[6]])));
                    }
                }
                0x7075 => {
                    if body.len() < 5 {
                        return Err(bad());
                    }
                    if u32_at(body, 1) == crc32(name) && std::str::from_utf8(&body[5..]).is_ok() {
                        shown = Some(&body[5..]);
                        entry.flags |= 0x0800;
                    }
                }
                _ => {}
            }
        }
        entry.name = shown.unwrap_or(name).into();
        entry.header = local;
        Ok(entry)
    }

    /// The entry of an archive that starts `archive` bytes into the file: its
    /// local header offset counted from the start of the file.
    fn placed(mut self, archive: u64) -> Result<Entry, Error> {
        self.header = self
            .header
            .checked_add(archive)
            .ok_or(Error::Directory("member offset past the end of the file"))?;
        Ok(self)
    }

    /// Whether the member is marked encrypted.
    pub(crate) fn encrypted(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Whether its name ends like a directory's.
    pub(crate) fn is_dir(&self) -> bool {
        matches!(self.name.last(), Some(b'/' | b'\\'))
    }

    /// Its name as text: UTF-8 when it is, else code page 437.
    pub(crate) fn name_text(&self) -> Cow<'_, str> {
        decode_name(&self.name)
    }

    /// When it was last modified: the time of its extended timestamp or NTFS
    /// field, else its DOS date and time when they are a real one.
    pub(crate) fn mtime(&self) -> Option<Mtime> {
        self.stamp.or_else(|| dos_time(self.date, self.time))
    }

    /// The high byte of its DOS time, `None` when the DOS date and time are
    /// not a real one: what ZipCrypto checks the password against in a member
    /// whose CRC-32 follows its data.
    pub(crate) fn dos_time_hi(&self) -> Option<u8> {
        dos_time(self.date, self.time).map(|_| (self.time >> 8) as u8)
    }

    /// Its Unix mode, from the high half of the external attributes when it
    /// was made on Unix (or any system but DOS) and from the DOS attributes
    /// when made on DOS. The set-id and sticky bits are dropped.
    pub(crate) fn unix_mode(&self) -> Option<u32> {
        const SPECIAL: u32 = 0o7000;
        if self.external == 0 {
            return None;
        }
        let high = self.external >> 16;
        match self.made_by >> 8 {
            0 => {
                let mut mode = if self.external & 0x10 != 0 {
                    0o040_775
                } else {
                    0o100_664
                };
                if self.external & 1 != 0 {
                    mode &= !0o222;
                }
                Some(mode)
            }
            3 => Some(high & !SPECIAL),
            _ => (high != 0).then_some(high & !SPECIAL),
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// A DOS date and time (4.4.6) as a wall-clock time, `None` when they name no
/// day. Sixty seconds read as 58.
fn dos_time(date: u16, time: u16) -> Option<Mtime> {
    let year = 1980 + (date >> 9);
    let month = ((date >> 5) & 0xF) as u8;
    let day = (date & 0x1F) as u8;
    let hour = (time >> 11) as u8;
    let minute = ((time >> 5) & 0x3F) as u8;
    let second = ((time & 0x1F) * 2) as u8;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(Mtime::Local {
        year,
        month,
        day,
        hour,
        minute,
        second: second.min(58),
    })
}

/// IBM code page 437 above ASCII (0x80 to 0xFF).
const CP437: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// `name` as text: itself when it is UTF-8, else read as code page 437.
pub(crate) fn decode_name(name: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(name) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(
            name.iter()
                .map(|&b| {
                    if b < 0x80 {
                        char::from(b)
                    } else {
                        CP437[usize::from(b) - 0x80]
                    }
                })
                .collect(),
        ),
    }
}

/// A ZIP's central directory.
pub(crate) struct Directory {
    /// In order of first appearance; a name used again keeps its place and
    /// takes the data of the last entry that has it.
    pub(crate) entries: Vec<Entry>,
    /// Where the central directory begins.
    pub(crate) start: u64,
    /// Where the archive begins: the offsets of its records count from it.
    pub(crate) archive_start: u64,
    /// The comment of the end record the directory was read from.
    pub(crate) comment: Vec<u8>,
}

impl Directory {
    /// The member named `name`, byte for byte.
    pub(crate) fn index_of(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| *e.name == *name.as_bytes())
    }
}

/// Where the offsets of the records count from.
#[derive(Clone, Copy)]
pub(crate) enum Origin {
    /// This many bytes into the file.
    Known(u64),
    /// Found from the offset the end record gives for the directory.
    Detect,
}

/// The directory of the archive in `r`, as the extraction walk opens one:
/// first as [`directory_shift`] says it lies (an archive after other bytes, or
/// a directory offset that is wrong while the members' are right), then with
/// the end record's own offsets.
///
/// An archive after other bytes (a self-extractor, an archive appended to a
/// file) has offsets that count from its own start. The directory ends where
/// the end record starts, so its real position is the record's less its size,
/// as Info-ZIP reckons it. When only the record's directory offset is wrong,
/// the members' offsets counting from the start of the file, the directory is
/// read with the record patched to point at it; `unzip` reads such an archive,
/// warning of "extra bytes".
pub(crate) fn open(r: &mut dyn ReadSeek) -> Result<Directory, Error> {
    match directory_shift(r) {
        Some(Shift::Prepended(n)) => {
            if let Ok(dir) = read(r, Origin::Known(n)) {
                return Ok(dir);
            }
        }
        Some(Shift::Misplaced { field, directory }) => {
            let mut patched = Patched::with(&mut *r, field, directory.to_le_bytes());
            if let Ok(dir) = read(&mut patched, Origin::Detect) {
                return Ok(dir);
            }
        }
        None => {}
    }
    read(r, Origin::Detect)
}

/// [`open`] for a package, which has its directory where its end record says:
/// taken so first, reading only the end of the file, where the search for a
/// shifted directory reads 64 KiB of it.
pub(crate) fn open_package(r: &mut dyn ReadSeek) -> Result<Directory, Error> {
    read(r, Origin::Known(0)).or_else(|_| open(r))
}

/// The directory of the last end record in `r` whose directory reads. The
/// records are those starting within [`END_REACH`] of the end of the file
/// whose comment ends in it, the last first; a record that fails (a disk
/// number, a ZIP64 locator that leads nowhere, an entry that does not parse)
/// leaves the one before it, except when the source lacks bytes it was asked
/// for.
///
/// A record whose entry count, directory size or directory offset is at its
/// maximum, with a ZIP64 locator before it, is read from the ZIP64 end record
/// instead. The size of the directory is never used: its entries are read from
/// where it starts, as many as the record counts.
pub(crate) fn read(r: &mut dyn ReadSeek, origin: Origin) -> Result<Directory, Error> {
    let len = r.seek(SeekFrom::End(0))?;
    let floor = len.saturating_sub(END_REACH);
    let mut end = len;
    let mut buf = Vec::new();
    let mut last = Error::Invalid("no end of central directory record");
    let mut seen = Seen::new();
    let mut chunk = EndRecord::LEN as u64;
    loop {
        // What is held of a chunk, when the source holds the end of the file only.
        let start = loop {
            let start = end.saturating_sub(chunk).max(floor);
            // The bytes of a record that begins in this chunk, past its end.
            let to = len.min(end + EndRecord::LEN as u64 - 1);
            r.seek(SeekFrom::Start(start))?;
            buf.clear();
            match (&mut *r).take(to - start).read_to_end(&mut buf) {
                Ok(_) => break start,
                Err(e) if missing(&e) && chunk > 1 => chunk /= 2,
                Err(e) => return Err(e.into()),
            }
        };
        chunk = END_CHUNK;
        for p in memchr::memmem::rfind_iter(&buf, b"PK\x05\x06") {
            let at = start + p as u64;
            if at >= end {
                continue;
            }
            let Some(rec) = EndRecord::parse(at, &buf[p..], len - at) else {
                continue;
            };
            match directory_of(r, len, &rec, origin, &mut seen) {
                Ok(dir) => return Ok(dir),
                Err(e) if e.is_missing() => return Err(e),
                Err(e) => last = e,
            }
        }
        if start == floor {
            return Err(last);
        }
        end = start;
    }
}

/// The directory `rec` describes.
fn directory_of(
    r: &mut dyn ReadSeek,
    len: u64,
    rec: &EndRecord,
    origin: Origin,
    seen: &mut Seen,
) -> Result<Directory, Error> {
    let saturated = rec.entries == u16::MAX || rec.size == u32::MAX || rec.offset == u32::MAX;
    let locator = match saturated {
        true => locator_before(r, rec.at)?,
        false => None,
    };
    let (count, start, archive_start) = match locator {
        Some(offset) => zip64_directory(r, len, seen, rec.at, offset, origin)?,
        None => classic_directory(r, len, seen, rec, origin)?,
    };
    let entries = seen.entries(r, len, start, count, archive_start)?;
    if let (Origin::Detect, Some(first)) = (origin, entries.first()) {
        // Bytes of the first member's local header, and of where the archive
        // starts, are asked of the source, which a source of the end of a file
        // answers with bytes it lacks: the directory then is not what it says.
        for at in [first.header - archive_start, archive_start] {
            let mut sig = [0u8; 4];
            r.seek(SeekFrom::Start(at))?;
            if let Err(e) = r.read_exact(&mut sig)
                && missing(&e)
            {
                return Err(e.into());
            }
        }
    }
    r.seek(SeekFrom::Start(rec.at + EndRecord::LEN as u64))?;
    let mut comment = Vec::new();
    (&mut *r)
        .take(u64::from(rec.comment))
        .read_to_end(&mut comment)?;
    Ok(Directory {
        entries: unique(entries),
        start,
        archive_start,
        comment,
    })
}

/// The offset of the ZIP64 end record, from the locator that ends where the
/// end record at `at` starts; `None` when there is no locator.
fn locator_before(r: &mut dyn ReadSeek, at: u64) -> Result<Option<u64>, Error> {
    let Some(from) = at.checked_sub(LOCATOR_LEN) else {
        return Ok(None);
    };
    let mut b = [0u8; LOCATOR_LEN as usize];
    r.seek(SeekFrom::Start(from))?;
    r.read_exact(&mut b)?;
    if !b.starts_with(LOCATOR_SIG) {
        return Ok(None);
    }
    // Disk with the ZIP64 end record, and number of disks.
    if u32_at(&b, 4) != 0 || u32_at(&b, 16) > 1 {
        return Err(Error::Invalid("ZIP64 archive over several disks"));
    }
    Ok(Some(u64_at(&b, 8)))
}

/// `(entries, where the directory starts, where the archive starts)` from the
/// ZIP64 end record the locator before `at` names at `offset`. The record is
/// the first one at or after that offset that ends where the locator starts,
/// which is how an archive after other bytes is found.
fn zip64_directory(
    r: &mut dyn ReadSeek,
    len: u64,
    seen: &mut Seen,
    at: u64,
    offset: u64,
    origin: Origin,
) -> Result<(u64, u64, u64), Error> {
    let bad = || Error::Invalid("invalid ZIP64 end of central directory record");
    let locator = at - LOCATOR_LEN;
    let mut b = [0u8; ZIP64_END_LEN];
    let mut from = offset;
    let rec_at = loop {
        let found = match origin {
            Origin::Known(n) => offset.checked_add(n),
            Origin::Detect => seen
                .zip64
                .first(r, len, ZIP64_END_SIG, from)?
                .filter(|q| q + 4 <= locator),
        };
        let rec_at = found.ok_or(Error::Invalid("no ZIP64 end of central directory record"))?;
        r.seek(SeekFrom::Start(rec_at))?;
        r.read_exact(&mut b)?;
        let ends_at = rec_at
            .checked_add(12)
            .and_then(|e| e.checked_add(u64_at(&b, 4)));
        if b.starts_with(ZIP64_END_SIG) && ends_at == Some(locator) {
            break rec_at;
        }
        if matches!(origin, Origin::Known(_)) {
            return Err(bad());
        }
        from = rec_at + 1;
    };
    // The disk it is on and the one the directory starts on, which are the
    // first, and the entries on this disk, which are no more than all of them.
    if u32_at(&b, 16) != 0 || u32_at(&b, 20) != 0 || u64_at(&b, 24) > u64_at(&b, 32) {
        return Err(Error::Invalid("ZIP64 archive over several disks"));
    }
    let archive = rec_at - offset;
    let count = u64_at(&b, 32);
    let declared = u64_at(&b, 48);
    // Room for the headers before the record.
    let room = count
        .checked_mul(CENTRAL_LEN as u64)
        .and_then(|n| declared.checked_add(n));
    if room.is_none_or(|end| end > rec_at) {
        return Err(Error::Invalid("directory offset past its end record"));
    }
    let start = declared
        .checked_add(archive)
        .ok_or(Error::Invalid("directory offset past the end of the file"))?;
    Ok((count, start, archive))
}

/// `(entries, where the directory starts, where the archive starts)` from the
/// fields of `rec` itself. The entries read are those held on this disk. With
/// no entries in all the directory is empty and ends at the record. Otherwise
/// the directory is at its offset, counted from the archive's start when that
/// is known, or else at the first central header from the offset on that ends
/// before the record. A directory starts before its record.
fn classic_directory(
    r: &mut dyn ReadSeek,
    len: u64,
    seen: &mut Seen,
    rec: &EndRecord,
    origin: Origin,
) -> Result<(u64, u64, u64), Error> {
    if rec.disk != rec.directory_disk {
        return Err(Error::Invalid("archive over several disks"));
    }
    let count = u64::from(rec.entries_here);
    let declared = u64::from(rec.offset);
    let (start, archive) = match origin {
        _ if rec.entries == 0 => {
            let archive = rec
                .at
                .checked_sub(declared)
                .ok_or(Error::Invalid("directory offset past its end record"))?;
            (Some(rec.at), archive)
        }
        Origin::Known(n) => (header_at(r, declared, n, rec.at)?, n),
        Origin::Detect => match header_at(r, declared, 0, rec.at)? {
            Some(at) => (Some(at), 0),
            None => {
                let found = seen
                    .header
                    .first(r, len, CENTRAL_SIG, declared)?
                    .filter(|q| q + 4 <= rec.at);
                (found, found.map_or(0, |f| f - declared))
            }
        },
    };
    let start = start.ok_or(Error::Invalid("no central directory where its offset says"))?;
    Ok((count, start, archive))
}

/// Where a central header starts, `shift` bytes after `declared`, which is
/// before the end record at `end`.
fn header_at(
    r: &mut dyn ReadSeek,
    declared: u64,
    shift: u64,
    end: u64,
) -> Result<Option<u64>, Error> {
    let Some(at) = declared.checked_add(shift).filter(|&at| at < end) else {
        return Ok(None);
    };
    let mut sig = [0u8; 4];
    r.seek(SeekFrom::Start(at))?;
    match r.read_exact(&mut sig) {
        Ok(()) => Ok((&sig == CENTRAL_SIG).then_some(at)),
        Err(e) if missing(&e) => Err(e.into()),
        Err(_) => Ok(None),
    }
}

/// Where a signature is first found from a place on, for the end records of a
/// file in turn, which ask for the same place more than once or for one
/// after a place that held none.
#[derive(Default)]
struct Finds {
    /// Where no signature starts, from there on.
    none_from: Option<u64>,
    found: std::collections::HashMap<u64, Option<u64>>,
}

impl Finds {
    /// The first place at or after `from` where `sig` starts, in a file of
    /// `len` bytes.
    fn first(
        &mut self,
        r: &mut dyn ReadSeek,
        len: u64,
        sig: &[u8; 4],
        from: u64,
    ) -> Result<Option<u64>, Error> {
        if self.none_from.is_some_and(|n| from >= n) {
            return Ok(None);
        }
        if let Some(&q) = self.found.get(&from) {
            return Ok(q);
        }
        // What lies from `none_from` on has been searched already.
        let until = self.none_from.map_or(len, |n| len.min(n.saturating_add(3)));
        let q = scan(r, sig, from, until)?;
        if q.is_some() {
            self.found.insert(from, q);
        } else {
            self.none_from = Some(from);
        }
        Ok(q)
    }
}

/// The first place in `[from, until)` where `sig` starts and ends within it.
fn scan(r: &mut dyn ReadSeek, sig: &[u8; 4], from: u64, until: u64) -> Result<Option<u64>, Error> {
    const CHUNK: u64 = 1 << 16;
    let mut at = from;
    let mut buf = Vec::new();
    while until.saturating_sub(at) >= 4 {
        let end = until.min(at.saturating_add(CHUNK));
        r.seek(SeekFrom::Start(at))?;
        buf.clear();
        (&mut *r).take(end - at).read_to_end(&mut buf)?;
        if let Some(i) = memchr::memmem::find(&buf, sig) {
            return Ok(Some(at + i as u64));
        }
        if end == until || (buf.len() as u64) < end - at {
            break;
        }
        // The next chunk begins inside this one's last 3 bytes, for a signature
        // across the seam.
        at = end - 3;
    }
    Ok(None)
}

/// The entries of a directory, read as far as they were asked for, and the
/// ones not yet asked for.
struct Stream {
    /// Where the next header is.
    next: u64,
    /// Read and not taken yet, in order. An entry that did not parse (an extra
    /// field) or that runs past the end of the file is an error here.
    held: std::collections::VecDeque<Result<Entry, &'static str>>,
    /// Whether what follows is not a header, or is cut by the end of the file.
    ended: bool,
}

/// The directories read so far, by where they start. Every end record that
/// points at the same place takes its entries from the same stream, in turn:
/// one that asks for more than the stream will ever hold fails and takes none;
/// one that gets an error among the entries it asks for takes them all, so
/// the next gets the entries after. The first to read a directory leaves
/// nothing of it when it fails on an error.
struct Seen {
    streams: std::collections::HashMap<u64, Stream>,
    /// Where central headers and ZIP64 end records were found.
    header: Finds,
    zip64: Finds,
}

impl Seen {
    fn new() -> Self {
        Seen {
            streams: std::collections::HashMap::new(),
            header: Finds::default(),
            zip64: Finds::default(),
        }
    }

    /// `count` entries of the directory at `at`, in an archive that starts
    /// `archive` bytes into the `len`-byte file.
    fn entries(
        &mut self,
        r: &mut dyn ReadSeek,
        len: u64,
        at: u64,
        count: u64,
        archive: u64,
    ) -> Result<Vec<Entry>, Error> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let first = !self.streams.contains_key(&at);
        let stream = self.streams.entry(at).or_insert_with(|| Stream {
            next: at,
            held: Default::default(),
            ended: false,
        });
        let want = usize::try_from(count).unwrap_or(usize::MAX);
        read_entries(r, len, stream, want)?;
        if stream.held.len() < want {
            return Err(Error::Invalid("central directory cut short"));
        }
        let taken: Vec<_> = stream.held.drain(..want).collect();
        let entries = taken
            .into_iter()
            .map(|e| e.map_err(Error::Directory).and_then(|e| e.placed(archive)))
            .collect::<Result<Vec<_>, _>>();
        if entries.is_err() && first {
            stream.held.clear();
            stream.ended = true;
        }
        entries
    }
}

/// Reads headers into `stream` until it holds `want` entries or ends. Each
/// costs 46 bytes of the `len`-byte file at least, so what is asked for past
/// the file ends where the file does.
fn read_entries(
    r: &mut dyn ReadSeek,
    len: u64,
    stream: &mut Stream,
    want: usize,
) -> Result<(), Error> {
    if stream.ended || stream.held.len() >= want {
        return Ok(());
    }
    r.seek(SeekFrom::Start(stream.next))?;
    let mut input = BufReader::with_capacity(1 << 15, r);
    let mut head = [0u8; CENTRAL_LEN];
    while stream.held.len() < want {
        let at = stream.next;
        match input.read_exact(&mut head) {
            Err(e) if missing(&e) => return Err(e.into()),
            Err(_) => {
                stream.ended = true;
                break;
            }
            Ok(()) => {}
        }
        let Some(h) = Header::parse(&head) else {
            stream.ended = true;
            break;
        };
        let end = at.saturating_add((CENTRAL_LEN + h.variable_len()) as u64);
        stream.next = end;
        if end > len {
            stream
                .held
                .push_back(Err("central directory runs past the end of the file"));
            if input.seek_relative(h.variable_len() as i64).is_err() {
                stream.ended = true;
            }
            continue;
        }
        let mut name = vec![0; h.name_len];
        let mut extra = vec![0; h.extra_len];
        let body = input
            .read_exact(&mut name)
            .and_then(|()| input.read_exact(&mut extra))
            .and_then(|()| input.seek_relative(h.comment_len as i64));
        if let Err(e) = body {
            if missing(&e) {
                return Err(e.into());
            }
            stream.ended = true;
            break;
        }
        stream
            .held
            .push_back(Entry::parse(&h, &name, &extra).map_err(|e| match e {
                Error::Directory(why) | Error::Invalid(why) => why,
                Error::Io(_) => "unreadable central directory",
            }));
    }
    Ok(())
}

/// Where the data of the member whose local header is at `header` starts
/// (4.3.7): `Ok(None)` when no local header is there (another signature, or
/// the file ends inside it), an error when the source fails.
pub(crate) fn local_header(r: &mut dyn ReadSeek, header: u64) -> std::io::Result<Option<u64>> {
    let mut h = [0u8; 30];
    r.seek(SeekFrom::Start(header))?;
    match r.read_exact(&mut h) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    if !h.starts_with(b"PK\x03\x04") {
        return Ok(None);
    }
    let name = u64::from(u16::from_le_bytes([h[26], h[27]]));
    let extra = u64::from(u16::from_le_bytes([h[28], h[29]]));
    Ok(header.checked_add(30 + name + extra))
}

/// [`local_header`] for a caller that takes a failing source as a header that
/// is not there.
pub(crate) fn local_data_start(r: &mut dyn ReadSeek, header: u64) -> Option<u64> {
    local_header(r, header).ok().flatten()
}

/// `entries` with each name once: at its first place, with the data of its
/// last entry.
fn unique(entries: Vec<Entry>) -> Vec<Entry> {
    let mut first: std::collections::HashMap<&[u8], usize> =
        std::collections::HashMap::with_capacity(entries.len());
    let mut winner: Vec<usize> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        match first.entry(&e.name[..]) {
            std::collections::hash_map::Entry::Occupied(o) => winner[*o.get()] = i,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(winner.len());
                winner.push(i);
            }
        }
    }
    drop(first);
    if winner.len() == entries.len() {
        return entries;
    }
    let mut slots: Vec<Option<Entry>> = entries.into_iter().map(Some).collect();
    winner.into_iter().filter_map(|i| slots[i].take()).collect()
}

/// Where a ZIP's central directory is, against where its end record says.
pub(crate) enum Shift {
    /// `n` bytes precede the archive, and every offset counts from its start.
    Prepended(u64),
    /// The directory is at `directory`, the end record's offset field at
    /// `field` says otherwise, and the members' offsets are right.
    Misplaced { field: u64, directory: u32 },
}

/// A reader over `inner` that reads the four bytes at `at` as `bytes`.
#[derive(Clone)]
pub(crate) struct Patched<R> {
    inner: R,
    at: u64,
    bytes: [u8; 4],
}

impl<R> Patched<R> {
    pub(crate) fn with(inner: R, at: u64, bytes: [u8; 4]) -> Self {
        Patched { inner, at, bytes }
    }
}

impl<R: Read + Seek> Read for Patched<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pos = self.inner.stream_position()?;
        let n = self.inner.read(buf)?;
        for (i, b) in self.bytes.iter().enumerate() {
            let Some(p) = self.at.checked_add(i as u64) else {
                break;
            };
            if let Some(slot) = p
                .checked_sub(pos)
                .and_then(|d| usize::try_from(d).ok())
                .and_then(|d| buf[..n].get_mut(d))
            {
                *slot = *b;
            }
        }
        Ok(n)
    }
}

impl<R: Seek> Seek for Patched<R> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// How a ZIP sits against its offsets, by the last end-of-central-directory
/// record in the file whose comment ends within it. `None` for ZIP64, an
/// empty archive, or no central header where that record puts the directory.
pub(crate) fn directory_shift(r: &mut dyn ReadSeek) -> Option<Shift> {
    directory_shift_within(r, u64::MAX)
}

/// [`directory_shift`] looking at the last `reach` bytes of the file and no
/// further back. An end record that closes an archive stapled to the end of a
/// file is within the longest comment of it, so a search for one that reads
/// the whole of a large file is a pass over it for nothing.
pub(crate) fn directory_shift_within(r: &mut dyn ReadSeek, reach: u64) -> Option<Shift> {
    const CHUNK: u64 = 1 << 16;
    let len = r.seek(SeekFrom::End(0)).ok()?;
    let mut rec = [0u8; EndRecord::LEN];
    let mut buf = Vec::new();
    // Chunks back from the end, each running 3 bytes into the next so a
    // signature across the seam is seen.
    let mut end = len;
    let found = 'found: loop {
        let start = end.saturating_sub(CHUNK);
        r.seek(SeekFrom::Start(start)).ok()?;
        buf.clear();
        (&mut *r).take(end - start).read_to_end(&mut buf).ok()?;
        for p in memchr::memmem::rfind_iter(&buf, b"PK\x05\x06") {
            let at = start + p as u64;
            r.seek(SeekFrom::Start(at)).ok()?;
            if r.read_exact(&mut rec).is_err() {
                continue;
            }
            if let Some(found) = EndRecord::parse(at, &rec, len - at) {
                break 'found found;
            }
        }
        if start == 0 || len - start >= reach {
            return None;
        }
        end = start + 3;
    };
    if !found.has_directory() {
        return None;
    }
    let at = found.at;
    let cd = at.checked_sub(u64::from(found.size))?;
    let n = cd.checked_sub(u64::from(found.offset))?;
    let mut head = [0u8; CENTRAL_LEN];
    r.seek(SeekFrom::Start(cd)).ok()?;
    r.read_exact(&mut head).ok()?;
    if !head.starts_with(CENTRAL_SIG) {
        return None;
    }
    // The first member's local header says which: shifted with the directory,
    // or where its offset puts it.
    let local = u64::from(u32::from_le_bytes([head[42], head[43], head[44], head[45]]));
    let mut is_local_header = |at: u64| {
        let mut sig = [0u8; 4];
        r.seek(SeekFrom::Start(at)).is_ok()
            && r.read_exact(&mut sig).is_ok()
            && sig == *b"PK\x03\x04"
    };
    if n > 0 && !is_local_header(local.saturating_add(n)) && is_local_header(local) {
        return Some(Shift::Misplaced {
            field: at + 16,
            directory: u32::try_from(cd).ok()?,
        });
    }
    Some(Shift::Prepended(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn local(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut b = b"PK\x03\x04\x14\0\0\0\0\0\0\0\x21\0".to_vec();
        b.extend_from_slice(&crc32(data).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(name);
        b.extend_from_slice(data);
        b
    }

    /// A central header: `fields` are made by, flags, time, date, external
    /// attributes, then the sizes (compressed, uncompressed) and the offset.
    struct Fields {
        made_by: u16,
        flags: u16,
        time: u16,
        date: u16,
        external: u32,
        sizes: (u32, u32),
        offset: u32,
    }

    fn header(name: &[u8], extra: &[u8], h: &Fields) -> Vec<u8> {
        let mut b = b"PK\x01\x02".to_vec();
        b.extend_from_slice(&h.made_by.to_le_bytes());
        b.extend_from_slice(&20u16.to_le_bytes());
        b.extend_from_slice(&h.flags.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&h.time.to_le_bytes());
        b.extend_from_slice(&h.date.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&h.sizes.0.to_le_bytes());
        b.extend_from_slice(&h.sizes.1.to_le_bytes());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0; 6]);
        b.extend_from_slice(&h.external.to_le_bytes());
        b.extend_from_slice(&h.offset.to_le_bytes());
        b.extend_from_slice(name);
        b.extend_from_slice(extra);
        b
    }

    fn plain(name: &[u8], offset: u32) -> Vec<u8> {
        header(
            name,
            b"",
            &Fields {
                made_by: 0x031e,
                flags: 0,
                time: 0,
                date: 0x21,
                external: 0o100_644 << 16,
                sizes: (1, 1),
                offset,
            },
        )
    }

    fn end(count: u16, size: u32, offset: u32, comment: &[u8]) -> Vec<u8> {
        let mut b = b"PK\x05\x06\0\0\0\0".to_vec();
        b.extend_from_slice(&count.to_le_bytes());
        b.extend_from_slice(&count.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        b.extend_from_slice(comment);
        b
    }

    /// Two members, `a` and `b`: the archive without its end record, and where
    /// the directory starts in it.
    fn two() -> (Vec<u8>, u32) {
        let mut body = local(b"a", b"x");
        let second = body.len() as u32;
        body.extend(local(b"b", b"y"));
        let at = body.len() as u32;
        body.extend(plain(b"a", 0));
        body.extend(plain(b"b", second));
        (body, at)
    }

    fn read_bytes(b: Vec<u8>, origin: Origin) -> Result<Directory, Error> {
        read(&mut Cursor::new(b), origin)
    }

    fn open_bytes(b: Vec<u8>) -> Result<Directory, Error> {
        open(&mut Cursor::new(b))
    }

    fn names(d: &Directory) -> Vec<&[u8]> {
        d.entries.iter().map(|e| &e.name[..]).collect()
    }

    #[test]
    fn a_directory_of_a_plain_archive() {
        let (mut b, at) = two();
        let size = b.len() as u32 - at;
        b.extend(end(2, size, at, b"note"));
        let d = open_bytes(b).unwrap();
        assert_eq!(names(&d), [b"a".as_slice(), b"b"]);
        assert_eq!((d.start, d.archive_start), (u64::from(at), 0));
        assert_eq!(d.comment, b"note");
        assert_eq!(d.entries[1].header, 32);
    }

    #[test]
    fn zip64_end_records_replace_the_fields_at_their_maximum() {
        let (mut b, at) = two();
        let size = b.len() as u64 - u64::from(at);
        let record = b.len() as u64;
        b.extend_from_slice(b"PK\x06\x06");
        b.extend_from_slice(&44u64.to_le_bytes());
        b.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        for v in [2u64, 2, size, u64::from(at)] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        b.extend_from_slice(&record.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend(end(u16::MAX, u32::MAX, u32::MAX, b""));
        let d = read_bytes(b, Origin::Detect).unwrap();
        assert_eq!(names(&d), [b"a".as_slice(), b"b"]);
        assert_eq!(d.start, u64::from(at));
    }

    #[test]
    fn zip64_sizes_and_offset_come_from_the_extra_field() {
        let mut b = local(b"a", b"x");
        let at = b.len() as u32;
        let mut extra = b"\x01\0\x18\0".to_vec();
        for v in [1u64 << 33, 1 << 34, 0] {
            extra.extend_from_slice(&v.to_le_bytes());
        }
        b.extend(header(
            b"a",
            &extra,
            &Fields {
                made_by: 0x031e,
                flags: 0,
                time: 0,
                date: 0x21,
                external: 0,
                sizes: (u32::MAX, u32::MAX),
                offset: u32::MAX,
            },
        ));
        let size = b.len() as u32 - at;
        b.extend(end(1, size, at, b""));
        let d = open_bytes(b).unwrap();
        let e = &d.entries[0];
        assert_eq!((e.size, e.compressed, e.header), (1 << 33, 1 << 34, 0));
    }

    #[test]
    fn bytes_before_the_archive_move_every_offset() {
        let (body, at) = two();
        let mut b = vec![b'x'; 25];
        b.extend(body);
        let size = b.len() as u32 - 25 - at;
        b.extend(end(2, size, at, b""));
        let d = open_bytes(b).unwrap();
        assert_eq!(d.archive_start, 25);
        assert_eq!(d.start, 25 + u64::from(at));
        assert_eq!(d.entries[1].header, 25 + 32);
    }

    #[test]
    fn a_directory_offset_that_ignores_the_bytes_before_leaves_the_members_in_place() {
        let mut b = vec![b'x'; 25];
        let (mut body, at) = (local(b"a", b"x"), 0);
        let _ = at;
        b.append(&mut body);
        let dir = b.len() as u32;
        b.extend(plain(b"a", 25));
        let size = b.len() as u32 - dir;
        b.extend(end(1, size, dir - 25, b""));
        let d = open_bytes(b).unwrap();
        assert_eq!((d.archive_start, d.start), (0, u64::from(dir)));
        assert_eq!(d.entries[0].header, 25);
    }

    #[test]
    fn a_record_with_a_cut_directory_leaves_the_record_before_it() {
        let (mut b, at) = two();
        let size = b.len() as u32 - at;
        b.extend(end(2, size, at, b""));
        b.extend(end(3, size, at, b""));
        let d = open_bytes(b.clone()).unwrap();
        assert_eq!(names(&d), [b"a".as_slice(), b"b"]);
        let cut = b.len() - 44;
        let mut only = b[..cut].to_vec();
        only.extend(end(3, size, at, b""));
        assert!(open_bytes(only).is_err());
    }

    #[test]
    fn a_name_used_twice_keeps_its_place_and_the_last_entry() {
        let mut b = local(b"a", b"x");
        let at = b.len() as u32;
        b.extend(plain(b"a", 0));
        b.extend(plain(b"b", 1));
        b.extend(plain(b"a", 2));
        let size = b.len() as u32 - at;
        b.extend(end(3, size, at, b""));
        let d = open_bytes(b).unwrap();
        assert_eq!(names(&d), [b"a".as_slice(), b"b"]);
        assert_eq!(d.entries[0].header, 2);
        assert_eq!(d.index_of("b"), Some(1));
    }

    #[test]
    fn an_extra_field_past_its_record_is_refused() {
        let h = |extra: &[u8]| {
            let mut b = local(b"a", b"x");
            let at = b.len() as u32;
            b.extend(header(
                b"a",
                extra,
                &Fields {
                    made_by: 0,
                    flags: 0,
                    time: 0,
                    date: 0x21,
                    external: 0,
                    sizes: (1, 1),
                    offset: 0,
                },
            ));
            let size = b.len() as u32 - at;
            b.extend(end(1, size, at, b""));
            open_bytes(b)
        };
        assert!(h(b"\x34\x12\x05\0abcd").is_err());
        assert!(h(b"\x34\x12\x04\0abcd").is_ok());
        // Fewer than four bytes left are not a field.
        assert!(h(b"\x34\x12\x04\0abcdxy").is_ok());
        // A ZIP64 field may claim more than it holds, when nothing is taken from it.
        assert!(h(b"\x01\0\xff\0ab").is_ok());
    }

    #[test]
    fn an_end_record_in_a_comment_does_not_hide_the_directory() {
        let (mut b, at) = two();
        let size = b.len() as u32 - at;
        // The real record's comment ends with a record that points nowhere.
        let fake = end(2, 1, 4000, b"");
        b.extend(end(2, size, at, &fake));
        let d = open_bytes(b).unwrap();
        assert_eq!(names(&d), [b"a".as_slice(), b"b"]);
        assert_eq!(d.comment, end(2, 1, 4000, b""));
        // One that does read is the last, and the one that is taken.
        let (mut b, at) = two();
        b.extend(end(2, size, at, &end(2, size, at, b"")));
        assert_eq!(open_bytes(b).unwrap().comment, b"");
    }

    #[test]
    fn a_tail_that_lacks_what_the_directory_points_at_is_asked_for_it() {
        use crate::formats::zip::{TailDirectory, directory_in_tail};
        let (mut file, at) = two();
        let size = file.len() as u32 - at;
        file.extend(end(2, size, at, b""));
        let whole = file.len() as u64;
        assert!(matches!(
            directory_in_tail(&file, whole),
            TailDirectory::Found(_)
        ));
        // The directory and the end record, not the first member.
        let tail = &file[at as usize..];
        assert_eq!(directory_in_tail(tail, whole), TailDirectory::Needs(0));
        // The last end record points before the tail, the one before it into it
        // (its directory is found from the tail on, and its first member is in
        // the tail too).
        let mut file = vec![b'x'; 200];
        let at = file.len() as u32;
        file.extend(plain(b"a", 150));
        let size = file.len() as u32 - at;
        file.extend(end(1, size, 100, b""));
        let tail = &file[100..];
        let whole = file.len() as u64;
        assert!(matches!(
            directory_in_tail(tail, whole),
            TailDirectory::Found(_)
        ));
        file.extend(end(1, size, 10, b""));
        let whole = file.len() as u64;
        assert!(matches!(
            directory_in_tail(&file[100..], whole),
            TailDirectory::Needs(_)
        ));
    }

    #[test]
    fn an_end_record_is_looked_for_in_the_last_bytes_only() {
        let (body, at) = two();
        let size = body.len() as u32 - at;
        let with_tail = |tail: u64| {
            let mut b = body.clone();
            b.extend(end(2, size, at, b""));
            b.resize(b.len() + usize::try_from(tail).unwrap(), b'x');
            open_bytes(b)
        };
        // The record starts 65572 bytes before the end, or one more.
        let record = EndRecord::LEN as u64;
        assert!(with_tail(65_572 - record).is_ok());
        assert!(with_tail(65_572 - record + 1).is_err());
    }

    #[test]
    fn end_records_that_point_at_one_directory_share_its_entries() {
        let mut dir = local(b"a", b"x");
        let at = dir.len() as u32;
        // An entry that does not parse (an empty extended timestamp), then one
        // that does.
        dir.extend(header(b"a", b"UT\0\0", &base()));
        dir.extend(plain(b"b", 0));
        let size = dir.len() as u32 - at;
        let with = |counts: &[u16]| {
            let mut b = dir.clone();
            for &c in counts {
                b.extend(end(c, size, at, b""));
            }
            read_bytes(b, Origin::Detect)
        };
        // The last record asks for the entry that does not parse and fails
        // with it: the one before has nothing of this directory left.
        assert!(with(&[1, 1]).is_err());
        // The last asks for more entries than there are, which takes none; the
        // next fails on the entry that does not parse, and the one before it
        // has the entry behind.
        assert_eq!(names(&with(&[1, 1, 3]).unwrap()), [b"b"]);
    }

    fn one_with(h: &Fields, name: &[u8], extra: &[u8]) -> Entry {
        let mut b = local(name, b"x");
        let at = b.len() as u32;
        b.extend(header(name, extra, h));
        let size = b.len() as u32 - at;
        b.extend(end(1, size, at, b""));
        open_bytes(b).unwrap().entries.remove(0)
    }

    fn base() -> Fields {
        Fields {
            made_by: 0x031e,
            flags: 0,
            time: 0,
            date: 0x21,
            external: 0o100_755 << 16,
            sizes: (1, 1),
            offset: 0,
        }
    }

    #[test]
    fn a_time_is_the_first_of_the_extra_fields_else_the_dos_time() {
        let ut = |t: u32| {
            let mut v = b"UT\x05\0\x01".to_vec();
            v.extend_from_slice(&t.to_le_bytes());
            v
        };
        let e = one_with(&base(), b"a", &ut(1_700_000_000));
        assert_eq!(e.mtime(), Some(Mtime::Unix(1_700_000_000)));
        // An extended timestamp field with no time is passed over; so is a
        // later one.
        let mut extra = b"UT\x01\0\x01".to_vec();
        extra.extend(ut(7));
        extra.extend(ut(9));
        assert_eq!(
            one_with(&base(), b"a", &extra).mtime(),
            Some(Mtime::Unix(7))
        );
        // NTFS: 100 ns ticks since 1601.
        let mut ntfs = b"\x0a\0\x20\0\0\0\0\0\x01\0\x18\0".to_vec();
        ntfs.extend_from_slice(&(11_644_473_600u64 * 10_000_000 + 30_000_000).to_le_bytes());
        ntfs.extend_from_slice(&[0; 16]);
        assert_eq!(one_with(&base(), b"a", &ntfs).mtime(), Some(Mtime::Unix(3)));
        // The DOS time: 2026-11-22 10:20:30, and none for a day that is not one.
        let dos = Fields {
            date: (46 << 9) | (11 << 5) | 22,
            time: (10 << 11) | (20 << 5) | 15,
            ..base()
        };
        assert_eq!(
            one_with(&dos, b"a", b"").mtime(),
            Some(Mtime::Local {
                year: 2026,
                month: 11,
                day: 22,
                hour: 10,
                minute: 20,
                second: 30
            })
        );
        let feb30 = Fields {
            date: (20 << 9) | (2 << 5) | 30,
            ..base()
        };
        assert_eq!(one_with(&feb30, b"a", b"").mtime(), None);
        let leap = Fields {
            date: (20 << 9) | (2 << 5) | 29,
            time: 30,
            ..base()
        };
        // 29 February 2000, and sixty seconds read as 58.
        assert!(matches!(
            one_with(&leap, b"a", b"").mtime(),
            Some(Mtime::Local {
                day: 29,
                second: 58,
                ..
            })
        ));
        let sixty_two = Fields { time: 31, ..base() };
        assert_eq!(one_with(&sixty_two, b"a", b"").mtime(), None);
    }

    #[test]
    fn the_aes_field_and_the_dos_time_byte_are_kept_for_the_decryption() {
        // Version 2, "AE", strength, the real method.
        let aes = |strength: u8, method: u16| {
            let mut v = b"\x01\x99\x07\0\x02\0AE".to_vec();
            v.push(strength);
            v.extend_from_slice(&method.to_le_bytes());
            v
        };
        assert_eq!(one_with(&base(), b"a", b"").aes, None);
        assert_eq!(one_with(&base(), b"a", &aes(3, 8)).aes, Some((3, 8)));
        // A field with no room for them is passed over, and the first with
        // room is the one.
        let mut extra = b"\x01\x99\x03\0\x02\0A".to_vec();
        extra.extend(aes(1, 0));
        extra.extend(aes(3, 8));
        assert_eq!(one_with(&base(), b"a", &extra).aes, Some((1, 0)));
        // The high byte of the DOS time 10:20:30, none for a day that is not one.
        let dos = Fields {
            date: (46 << 9) | (11 << 5) | 22,
            time: (10 << 11) | (20 << 5) | 15,
            ..base()
        };
        assert_eq!(one_with(&dos, b"a", b"").dos_time_hi(), Some(0x52));
        let feb30 = Fields {
            date: (20 << 9) | (2 << 5) | 30,
            ..dos
        };
        assert_eq!(one_with(&feb30, b"a", b"").dos_time_hi(), None);
    }

    #[test]
    fn a_mode_is_from_the_external_attributes_by_the_system_that_made_it() {
        let mode = |made_by: u16, external: u32| {
            one_with(
                &Fields {
                    made_by,
                    external,
                    ..base()
                },
                b"a",
                b"",
            )
            .unix_mode()
        };
        // Unix: the high half, without set-id and sticky bits.
        assert_eq!(mode(0x031e, 0o104_755 << 16), Some(0o100_755));
        assert_eq!(mode(0x031e, 0o040_755 << 16), Some(0o040_755));
        assert_eq!(mode(0x031e, 0), None);
        // DOS: a file or a directory, read-only or not.
        assert_eq!(mode(0x001e, 0x20), Some(0o100_664));
        assert_eq!(mode(0x001e, 0x01), Some(0o100_444));
        assert_eq!(mode(0x001e, 0x11), Some(0o040_555));
        // Another system: the high half when there is one.
        assert_eq!(mode(0x0a1e, 0o100_600 << 16), Some(0o100_600));
        assert_eq!(mode(0x0a1e, 0x20), None);
    }

    #[test]
    fn a_name_is_the_unicode_path_when_its_checksum_is_the_names() {
        let path = |crc: u32, name: &str| {
            let mut v = b"up".to_vec();
            v.extend_from_slice(&(5 + name.len() as u16).to_le_bytes());
            v.push(1);
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(name.as_bytes());
            v
        };
        let raw = b"caf\xe9.txt";
        let e = one_with(&base(), raw, &path(crc32(raw), "caf\u{e9}.txt"));
        assert_eq!(&e.name[..], "caf\u{e9}.txt".as_bytes());
        assert_eq!(e.flags & 0x0800, 0x0800);
        assert!(!e.is_dir());
        // A name that ends with a slash or a backslash is a directory's.
        assert!(one_with(&base(), b"d/", b"").is_dir());
        assert!(one_with(&base(), b"d\\", b"").is_dir());
        let wrong = one_with(&base(), raw, &path(crc32(raw) ^ 1, "x"));
        assert_eq!(&wrong.name[..], raw);
        assert_eq!(wrong.flags & 0x0800, 0);
        // Not UTF-8 text, a name as the code page 437 reads it.
        assert_eq!(wrong.name_text(), "caf\u{398}.txt");
        assert_eq!(decode_name(b"\x80\xff"), "\u{c7}\u{a0}");
    }
}
