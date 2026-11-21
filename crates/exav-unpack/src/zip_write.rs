//! A ZIP writer, from PKWARE's APPNOTE.TXT: the subset exav's converters and
//! fixtures use. Members are Stored or Deflated, with a fixed DOS time unless
//! the caller sets one, and no extra fields except ZIP64's. The output must
//! support `Seek`: a member's local header is written first and patched with
//! its CRC and sizes when the member ends. Feature `zip-write`.
//!
//! ZIP64 records are written when the file needs them: a central directory
//! entry whose offset or size does not fit 32 bits, or a directory past 65534
//! members or 4 GiB. A single member that may pass 4 GiB must be started with
//! [`FileOptions::large_file`], because its local header is written before its
//! size is known; without it, the write that crosses the limit fails.
//!
//! The writer is generic over its output `W` only in a thin shell: the state
//! machine takes `&mut dyn Sink`, so it is compiled once whatever `W` is.

use std::collections::HashSet;
use std::io::{self, Seek, SeekFrom, Write};

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};

#[cfg(feature = "test-util")]
use crate::zip_keys::ZipCryptoKeys;

const LOCAL_SIG: u32 = 0x0403_4b50;
const DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const END_SIG: u32 = 0x0605_4b50;
const END64_SIG: u32 = 0x0606_4b50;
const LOCATOR64_SIG: u32 = 0x0706_4b50;
const ZIP64_EXTRA: u16 = 0x0001;

/// General purpose flag bits.
const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAG_UTF8: u16 = 0x0800;

/// DOS date of 1980-01-01, the earliest one.
const DOS_DATE_EPOCH: u16 = (1 << 5) | 1;
/// Version made by: host system 3 (Unix), so that the external attributes
/// hold a Unix mode.
const HOST_UNIX: u16 = 3 << 8;
const MODE_FILE: u32 = 0o100_644;
/// The level `flate2` gives a deflater by default.
const DEFAULT_LEVEL: u32 = 6;
/// Marks a 16-bit field whose value is in the ZIP64 record.
const MARK16: u64 = 0xFFFF;
/// Marks a 32-bit field whose value is in the ZIP64 record or extra field.
const MARK32: u64 = 0xFFFF_FFFF;

/// How a member's bytes are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflated,
}

/// What a member is written with. The default is Deflated at the level
/// `flate2` defaults to, dated 1980-01-01 00:00:00.
#[derive(Clone, Copy)]
pub struct FileOptions {
    method: Method,
    level: Option<u32>,
    date: u16,
    time: u16,
    large_file: bool,
    #[cfg(feature = "test-util")]
    keys: Option<ZipCryptoKeys>,
}

impl Default for FileOptions {
    fn default() -> Self {
        FileOptions {
            method: Method::Deflated,
            level: None,
            date: DOS_DATE_EPOCH,
            time: 0,
            large_file: false,
            #[cfg(feature = "test-util")]
            keys: None,
        }
    }
}

impl FileOptions {
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// The deflate level, 0 to 9 (more is taken as 9). `None` is the default.
    pub fn level(mut self, level: Option<u32>) -> Self {
        self.level = level;
        self
    }

    /// The member's modification time, as the MS-DOS date and time fields.
    pub fn modified(mut self, date: u16, time: u16) -> Self {
        self.date = date;
        self.time = time;
        self
    }

    /// Reserves ZIP64 sizes in the member's local header, so that it may pass
    /// 4 GiB.
    pub fn large_file(mut self, large: bool) -> Self {
        self.large_file = large;
        self
    }

    /// Encrypts the member with the traditional ZIP cipher. Feature
    /// `test-util`, for fixtures only: the cipher is broken, and the 12 bytes
    /// of its header are not random.
    #[cfg(feature = "test-util")]
    pub fn zipcrypto(mut self, password: &[u8]) -> Self {
        self.keys = Some(ZipCryptoKeys::new(password));
        self
    }
}

/// An output that can be written and patched.
trait Sink: Write + Seek {}
impl<T: Write + Seek> Sink for T {}

/// What the central directory records of a member.
struct Member {
    name: Box<str>,
    flags: u16,
    method: u16,
    version: u16,
    date: u16,
    time: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    offset: u64,
    large: bool,
}

/// The member being written.
struct Open {
    m: Member,
    crc: Crc,
    deflate: Option<DeflateEncoder<Vec<u8>>>,
    #[cfg(feature = "test-util")]
    keys: Option<ZipCryptoKeys>,
    #[cfg(feature = "test-util")]
    scratch: Vec<u8>,
}

struct State {
    /// Bytes written so far: the output is taken to start at 0.
    pos: u64,
    members: Vec<Member>,
    names: HashSet<Box<str>>,
    open: Option<Open>,
    comment: Vec<u8>,
    /// The value from which a 32-bit field goes to the ZIP64 record, and the
    /// same for a 16-bit one. Format constants; tests lower them.
    max32: u64,
    max16: u64,
}

/// A ZIP archive written to `W`. Dropping it without calling `finish` writes
/// no central directory.
pub struct ZipWriter<W: Write + Seek> {
    out: W,
    state: State,
}

impl<W: Write + Seek> ZipWriter<W> {
    /// A writer to `out`, which must be at its start.
    pub fn new(out: W) -> Self {
        ZipWriter {
            out,
            state: State {
                pos: 0,
                members: Vec::new(),
                names: HashSet::new(),
                open: None,
                comment: Vec::new(),
                max32: MARK32,
                max16: MARK16,
            },
        }
    }

    /// Ends the member being written, if any, and starts a new one. A
    /// duplicate name is refused.
    pub fn start_file(&mut self, name: &str, options: FileOptions) -> io::Result<()> {
        self.state.start(&mut self.out, name, options)
    }

    /// The archive's comment.
    pub fn set_comment(&mut self, comment: &str) -> io::Result<()> {
        if comment.len() > usize::from(u16::MAX) {
            return Err(invalid("the ZIP comment is over 65535 bytes"));
        }
        self.state.comment = comment.as_bytes().to_vec();
        Ok(())
    }

    /// Writes the central directory and returns the output.
    pub fn finish(mut self) -> io::Result<W> {
        self.state.finish(&mut self.out)?;
        self.out.flush()?;
        Ok(self.out)
    }

    #[cfg(test)]
    fn with_thresholds(mut self, max16: u64, max32: u64) -> Self {
        self.state.max16 = max16;
        self.state.max32 = max32;
        self
    }
}

impl<W: Write + Seek> Write for ZipWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.state.put(&mut self.out, data)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn too_large() -> io::Error {
    io::Error::other("ZIP member too large without the large_file option")
}

fn u16le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn u32le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn u64le(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

impl State {
    fn start(&mut self, out: &mut dyn Sink, name: &str, o: FileOptions) -> io::Result<()> {
        self.close(out)?;
        if name.len() > usize::from(u16::MAX) {
            return Err(invalid("a ZIP member name is over 65535 bytes"));
        }
        if !self.names.insert(name.into()) {
            return Err(invalid("a ZIP member name is used twice"));
        }
        #[cfg(feature = "test-util")]
        let encrypted = o.keys.is_some();
        #[cfg(not(feature = "test-util"))]
        let encrypted = false;
        let mut flags = if name.is_ascii() { 0 } else { FLAG_UTF8 };
        if encrypted {
            flags |= FLAG_ENCRYPTED | FLAG_DESCRIPTOR;
        }
        let version = if o.large_file {
            45
        } else if encrypted || o.method == Method::Deflated {
            20
        } else {
            10
        };
        let m = Member {
            name: name.into(),
            flags,
            method: match o.method {
                Method::Stored => 0,
                Method::Deflated => 8,
            },
            version,
            date: o.date,
            time: o.time,
            crc: 0,
            csize: 0,
            usize: 0,
            offset: self.pos,
            large: o.large_file,
        };
        let header = local_header(&m);
        out.write_all(&header)?;
        self.pos += header.len() as u64;
        let deflate = (o.method == Method::Deflated).then(|| {
            let level = o.level.unwrap_or(DEFAULT_LEVEL).min(9);
            DeflateEncoder::new(Vec::new(), Compression::new(level))
        });
        let mut open = Open {
            m,
            crc: Crc::new(),
            deflate,
            #[cfg(feature = "test-util")]
            keys: o.keys,
            #[cfg(feature = "test-util")]
            scratch: Vec::new(),
        };
        if encrypted {
            // The last byte is what a reader checks the password with: with
            // a data descriptor, the high byte of the time.
            let mut head = [0u8; 12];
            head[11] = (o.time >> 8) as u8;
            open.emit(out, &head, self.max32, &mut self.pos)?;
        }
        self.open = Some(open);
        Ok(())
    }

    fn put(&mut self, out: &mut dyn Sink, data: &[u8]) -> io::Result<()> {
        let Some(open) = self.open.as_mut() else {
            return Err(io::Error::other("no ZIP member has been started"));
        };
        open.crc.update(data);
        open.m.usize += data.len() as u64;
        if !open.m.large && open.m.usize >= self.max32 {
            return Err(too_large());
        }
        if open.deflate.is_none() {
            return open.emit(out, data, self.max32, &mut self.pos);
        }
        let mut rest = data;
        while !rest.is_empty() {
            let Some(enc) = open.deflate.as_mut() else {
                break;
            };
            let n = enc.write(rest)?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            rest = &rest[n..];
            let mut buf = std::mem::take(enc.get_mut());
            let r = open.emit(out, &buf, self.max32, &mut self.pos);
            buf.clear();
            if let Some(enc) = open.deflate.as_mut() {
                *enc.get_mut() = buf;
            }
            r?;
        }
        Ok(())
    }

    /// Ends the open member: its last compressed bytes, then its CRC and
    /// sizes, in a data descriptor or in its local header.
    fn close(&mut self, out: &mut dyn Sink) -> io::Result<()> {
        let Some(mut open) = self.open.take() else {
            return Ok(());
        };
        if let Some(enc) = open.deflate.take() {
            let tail = enc.finish()?;
            open.emit(out, &tail, self.max32, &mut self.pos)?;
        }
        let m = &mut open.m;
        m.crc = open.crc.sum();
        if m.flags & FLAG_DESCRIPTOR != 0 {
            let mut d = Vec::new();
            u32le(&mut d, DESCRIPTOR_SIG);
            u32le(&mut d, m.crc);
            if m.large {
                u64le(&mut d, m.csize);
                u64le(&mut d, m.usize);
            } else {
                u32le(&mut d, m.csize as u32);
                u32le(&mut d, m.usize as u32);
            }
            out.write_all(&d)?;
            self.pos += d.len() as u64;
        } else {
            let mut patch = Vec::new();
            u32le(&mut patch, m.crc);
            if !m.large {
                u32le(&mut patch, m.csize as u32);
                u32le(&mut patch, m.usize as u32);
            }
            out.seek(SeekFrom::Start(m.offset + 14))?;
            out.write_all(&patch)?;
            if m.large {
                // Both sizes are in the local header's ZIP64 extra field.
                let mut sizes = Vec::new();
                u64le(&mut sizes, m.usize);
                u64le(&mut sizes, m.csize);
                out.seek(SeekFrom::Start(m.offset + 30 + m.name.len() as u64 + 4))?;
                out.write_all(&sizes)?;
            }
            out.seek(SeekFrom::Start(self.pos))?;
        }
        self.members.push(open.m);
        Ok(())
    }

    fn finish(&mut self, out: &mut dyn Sink) -> io::Result<()> {
        self.close(out)?;
        let dir_offset = self.pos;
        for m in &self.members {
            let record = central_record(m, self.max32);
            out.write_all(&record)?;
            self.pos += record.len() as u64;
        }
        let dir_size = self.pos - dir_offset;
        let count = self.members.len() as u64;
        let zip64 = count >= self.max16 || dir_size >= self.max32 || dir_offset >= self.max32;
        let mut end = Vec::new();
        if zip64 {
            let end64_at = self.pos;
            u32le(&mut end, END64_SIG);
            // The record's size after this field: nothing follows its
            // fixed part.
            u64le(&mut end, 44);
            u16le(&mut end, HOST_UNIX | 45);
            u16le(&mut end, 45);
            u32le(&mut end, 0);
            u32le(&mut end, 0);
            u64le(&mut end, count);
            u64le(&mut end, count);
            u64le(&mut end, dir_size);
            u64le(&mut end, dir_offset);
            u32le(&mut end, LOCATOR64_SIG);
            u32le(&mut end, 0);
            u64le(&mut end, end64_at);
            u32le(&mut end, 1);
        }
        u32le(&mut end, END_SIG);
        u16le(&mut end, 0);
        u16le(&mut end, 0);
        if zip64 {
            u16le(&mut end, MARK16 as u16);
            u16le(&mut end, MARK16 as u16);
            u32le(&mut end, MARK32 as u32);
            u32le(&mut end, MARK32 as u32);
        } else {
            u16le(&mut end, count as u16);
            u16le(&mut end, count as u16);
            u32le(&mut end, dir_size as u32);
            u32le(&mut end, dir_offset as u32);
        }
        u16le(&mut end, self.comment.len() as u16);
        end.extend_from_slice(&self.comment);
        out.write_all(&end)?;
        self.pos += end.len() as u64;
        Ok(())
    }
}

impl Open {
    /// Writes bytes of the member's stored data, encrypted when it is, and
    /// counts them in its compressed size.
    fn emit(
        &mut self,
        out: &mut dyn Sink,
        bytes: &[u8],
        max32: u64,
        pos: &mut u64,
    ) -> io::Result<()> {
        #[cfg(feature = "test-util")]
        match self.keys.as_mut() {
            None => out.write_all(bytes)?,
            Some(keys) => {
                for chunk in bytes.chunks(8192) {
                    self.scratch.clear();
                    for &p in chunk {
                        self.scratch.push(p ^ keys.stream_byte());
                        keys.update(p);
                    }
                    out.write_all(&self.scratch)?;
                }
            }
        }
        #[cfg(not(feature = "test-util"))]
        out.write_all(bytes)?;
        self.m.csize += bytes.len() as u64;
        *pos += bytes.len() as u64;
        if !self.m.large && self.m.csize >= max32 {
            return Err(too_large());
        }
        Ok(())
    }
}

/// A member's local file header, with zero CRC and sizes, or their ZIP64
/// markers and room for them in the extra field.
fn local_header(m: &Member) -> Vec<u8> {
    let mut h = Vec::with_capacity(30 + m.name.len() + 20);
    u32le(&mut h, LOCAL_SIG);
    u16le(&mut h, m.version);
    u16le(&mut h, m.flags);
    u16le(&mut h, m.method);
    u16le(&mut h, m.time);
    u16le(&mut h, m.date);
    u32le(&mut h, 0);
    let size = if m.large { MARK32 as u32 } else { 0 };
    u32le(&mut h, size);
    u32le(&mut h, size);
    u16le(&mut h, m.name.len() as u16);
    u16le(&mut h, if m.large { 20 } else { 0 });
    h.extend_from_slice(m.name.as_bytes());
    if m.large {
        u16le(&mut h, ZIP64_EXTRA);
        u16le(&mut h, 16);
        u64le(&mut h, 0);
        u64le(&mut h, 0);
    }
    h
}

/// A member's central directory record.
fn central_record(m: &Member, max32: u64) -> Vec<u8> {
    let big_usize = m.usize >= max32;
    let big_csize = m.csize >= max32;
    let big_offset = m.offset >= max32;
    let mut extra = Vec::new();
    if big_usize || big_csize || big_offset {
        let mut data = Vec::new();
        if big_usize {
            u64le(&mut data, m.usize);
        }
        if big_csize {
            u64le(&mut data, m.csize);
        }
        if big_offset {
            u64le(&mut data, m.offset);
        }
        u16le(&mut extra, ZIP64_EXTRA);
        u16le(&mut extra, data.len() as u16);
        extra.extend_from_slice(&data);
    }
    let version = if m.large || !extra.is_empty() {
        45
    } else {
        m.version
    };
    let field = |big: bool, v: u64| if big { MARK32 as u32 } else { v as u32 };
    let mut r = Vec::with_capacity(46 + m.name.len() + extra.len());
    u32le(&mut r, CENTRAL_SIG);
    u16le(&mut r, HOST_UNIX | version);
    u16le(&mut r, version);
    u16le(&mut r, m.flags);
    u16le(&mut r, m.method);
    u16le(&mut r, m.time);
    u16le(&mut r, m.date);
    u32le(&mut r, m.crc);
    u32le(&mut r, field(big_csize, m.csize));
    u32le(&mut r, field(big_usize, m.usize));
    u16le(&mut r, m.name.len() as u16);
    u16le(&mut r, extra.len() as u16);
    // No comment, disk 0, no internal attributes.
    u16le(&mut r, 0);
    u16le(&mut r, 0);
    u16le(&mut r, 0);
    u32le(&mut r, MODE_FILE << 16);
    u32le(&mut r, field(big_offset, m.offset));
    r.extend_from_slice(m.name.as_bytes());
    r.extend_from_slice(&extra);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    /// A central directory record, read by hand from APPNOTE.TXT's layout.
    #[derive(Debug)]
    struct Entry {
        name: Vec<u8>,
        needed: u16,
        flags: u16,
        method: u16,
        time: u16,
        date: u16,
        crc: u32,
        csize: u64,
        usize: u64,
        offset: u64,
        mode: u32,
    }

    struct Directory {
        entries: Vec<Entry>,
        zip64: bool,
        comment: Vec<u8>,
    }

    fn le(b: &[u8], at: usize, n: usize) -> u64 {
        b[at..at + n]
            .iter()
            .rev()
            .fold(0u64, |a, &x| (a << 8) | u64::from(x))
    }

    fn directory(z: &[u8]) -> Directory {
        let end = z.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
        let clen = le(z, end + 20, 2) as usize;
        assert_eq!(end + 22 + clen, z.len(), "the end record closes the file");
        let comment = z[end + 22..].to_vec();
        let (mut count, mut size, mut at) =
            (le(z, end + 10, 2), le(z, end + 12, 4), le(z, end + 16, 4));
        let zip64 = count == 0xFFFF || size == 0xFFFF_FFFF || at == 0xFFFF_FFFF;
        if zip64 {
            assert_eq!(le(z, end - 20, 4), 0x0706_4b50, "locator");
            let end64 = le(z, end - 12, 8) as usize;
            assert_eq!(&z[end64..end64 + 4], b"PK\x06\x06");
            assert_eq!(end64 + 56 + 20, end, "the records are adjacent");
            assert_eq!(le(z, end64 + 4, 8), 44);
            count = le(z, end64 + 32, 8);
            size = le(z, end64 + 40, 8);
            at = le(z, end64 + 48, 8);
        }
        let mut entries = Vec::new();
        let mut p = at as usize;
        for _ in 0..count {
            assert_eq!(&z[p..p + 4], b"PK\x01\x02");
            let (n, x, c) = (le(z, p + 28, 2), le(z, p + 30, 2), le(z, p + 32, 2));
            let mut e = Entry {
                name: z[p + 46..p + 46 + n as usize].to_vec(),
                needed: le(z, p + 6, 2) as u16,
                flags: le(z, p + 8, 2) as u16,
                method: le(z, p + 10, 2) as u16,
                time: le(z, p + 12, 2) as u16,
                date: le(z, p + 14, 2) as u16,
                crc: le(z, p + 16, 4) as u32,
                csize: le(z, p + 20, 4),
                usize: le(z, p + 24, 4),
                offset: le(z, p + 42, 4),
                mode: (le(z, p + 38, 4) >> 16) as u32,
            };
            assert_eq!(le(z, p + 4, 2) >> 8, 3, "made on Unix");
            let mut extra = &z[p + 46 + n as usize..p + 46 + (n + x) as usize];
            while !extra.is_empty() {
                let (id, len) = (le(extra, 0, 2), le(extra, 2, 2) as usize);
                assert_eq!(id, 1, "ZIP64 is the only extra field");
                let mut f = &extra[4..4 + len];
                for v in [&mut e.usize, &mut e.csize, &mut e.offset] {
                    if *v == 0xFFFF_FFFF {
                        *v = le(f, 0, 8);
                        f = &f[8..];
                    }
                }
                assert!(f.is_empty(), "the field holds what the markers say");
                extra = &extra[4 + len..];
            }
            p += 46 + (n + x + c) as usize;
            entries.push(e);
        }
        assert_eq!(p as u64, at + size, "the directory is as long as said");
        Directory {
            entries,
            zip64,
            comment,
        }
    }

    /// The member's bytes, read through its local header; its CRC and sizes
    /// are checked against the directory's.
    fn member(z: &[u8], e: &Entry) -> Vec<u8> {
        let p = e.offset as usize;
        assert_eq!(&z[p..p + 4], b"PK\x03\x04");
        let (n, x) = (le(z, p + 26, 2) as usize, le(z, p + 28, 2) as usize);
        assert_eq!(&z[p + 30..p + 30 + n], &e.name[..]);
        assert_eq!(le(z, p + 6, 2) as u16, e.flags);
        assert_eq!(le(z, p + 8, 2) as u16, e.method);
        if e.flags & FLAG_DESCRIPTOR == 0 {
            assert_eq!(le(z, p + 14, 4) as u32, e.crc);
            if x == 0 {
                assert_eq!(le(z, p + 18, 4), e.csize);
                assert_eq!(le(z, p + 22, 4), e.usize);
            } else {
                assert_eq!(le(z, p + 18, 4), 0xFFFF_FFFF);
                assert_eq!(le(z, p + 30 + n, 2), 1);
                assert_eq!(le(z, p + 30 + n + 2, 2), 16);
                assert_eq!(le(z, p + 30 + n + 4, 8), e.usize);
                assert_eq!(le(z, p + 30 + n + 12, 8), e.csize);
            }
        }
        let start = p + 30 + n + x;
        let raw = &z[start..start + e.csize as usize];
        let data = match e.method {
            0 => raw.to_vec(),
            8 => {
                let mut v = Vec::new();
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut v)
                    .unwrap();
                v
            }
            m => panic!("method {m}"),
        };
        assert_eq!(data.len() as u64, e.usize);
        let mut crc = Crc::new();
        crc.update(&data);
        assert_eq!(crc.sum(), e.crc);
        data
    }

    fn zip_of(members: &[(&str, Method, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, method, data) in members {
            w.start_file(name, FileOptions::default().method(*method))
                .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn stored_and_deflated_members_read_back() {
        let big: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(i) >> 7) as u8)
            .collect();
        let z = zip_of(&[
            ("a.txt", Method::Stored, b"hello"),
            ("dir/b.bin", Method::Deflated, &big),
            ("c", Method::Deflated, b"hello hello hello hello"),
        ]);
        let d = directory(&z);
        assert!(!d.zip64);
        let names: Vec<&[u8]> = d.entries.iter().map(|e| &e.name[..]).collect();
        assert_eq!(names, [&b"a.txt"[..], b"dir/b.bin", b"c"]);
        assert_eq!(
            d.entries.iter().map(|e| e.method).collect::<Vec<_>>(),
            [0, 8, 8]
        );
        assert_eq!(
            d.entries.iter().map(|e| e.needed).collect::<Vec<_>>(),
            [10, 20, 20]
        );
        // The CRC-32 of "hello", from an independent implementation.
        assert_eq!(d.entries[0].crc, 0x3610_a686);
        assert_eq!(member(&z, &d.entries[0]), b"hello");
        assert_eq!(member(&z, &d.entries[1]), big);
        assert!(d.entries[1].csize < d.entries[1].usize);
        assert_eq!(member(&z, &d.entries[2]), b"hello hello hello hello");
        for e in &d.entries {
            assert_eq!((e.date, e.time, e.flags, e.mode), (0x21, 0, 0, 0o100_644));
        }
    }

    #[test]
    fn empty_members_and_an_empty_archive() {
        let z = zip_of(&[("s", Method::Stored, b""), ("d", Method::Deflated, b"")]);
        let d = directory(&z);
        assert_eq!((d.entries[0].csize, d.entries[0].usize), (0, 0));
        // An empty deflate stream is one final empty block.
        assert_eq!((d.entries[1].csize, d.entries[1].usize), (2, 0));
        assert_eq!(member(&z, &d.entries[1]), b"");
        let z = zip_of(&[]);
        assert_eq!(z, b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        assert!(directory(&z).entries.is_empty());
    }

    #[test]
    fn many_members_each_at_its_own_offset() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..1500u32 {
            let method = if i % 2 == 0 {
                Method::Stored
            } else {
                Method::Deflated
            };
            w.start_file(&format!("p/{i}.xml"), FileOptions::default().method(method))
                .unwrap();
            // Written in pieces, the way a converter does.
            for _ in 0..(i % 5) {
                w.write_all(format!("<m {i}/>").as_bytes()).unwrap();
            }
        }
        let z = w.finish().unwrap().into_inner();
        let d = directory(&z);
        assert_eq!(d.entries.len(), 1500);
        for (i, e) in d.entries.iter().enumerate() {
            assert_eq!(e.name, format!("p/{i}.xml").as_bytes());
            assert_eq!(member(&z, e), format!("<m {i}/>").repeat(i % 5).as_bytes());
        }
    }

    #[test]
    fn a_name_with_non_ascii_bytes_is_flagged_utf8() {
        let z = zip_of(&[
            ("é/ü.txt", Method::Stored, b"x"),
            ("plain", Method::Stored, b"y"),
        ]);
        let d = directory(&z);
        assert_eq!(d.entries[0].name, "é/ü.txt".as_bytes());
        assert_eq!(d.entries[0].flags, FLAG_UTF8);
        assert_eq!(d.entries[1].flags, 0);
        assert_eq!(member(&z, &d.entries[0]), b"x");
    }

    #[test]
    fn a_time_and_a_comment_are_kept() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let at = FileOptions::default().modified(0x5a21, 0x7d3f);
        w.start_file("t", at.method(Method::Stored)).unwrap();
        w.set_comment("a comment").unwrap();
        let z = w.finish().unwrap().into_inner();
        let d = directory(&z);
        assert_eq!((d.entries[0].date, d.entries[0].time), (0x5a21, 0x7d3f));
        assert_eq!(d.comment, b"a comment");
    }

    #[test]
    fn a_name_used_twice_or_a_write_with_no_member_is_refused() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        assert!(w.write_all(b"x").is_err());
        w.start_file("a", FileOptions::default()).unwrap();
        assert!(w.start_file("a", FileOptions::default()).is_err());
        assert!(
            w.start_file(&"n".repeat(65_536), FileOptions::default())
                .is_err()
        );
    }

    /// Past 65534 members the end record points to the ZIP64 one.
    #[test]
    fn a_directory_of_many_members_gets_zip64_records() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..70_000u32 {
            w.start_file(
                &i.to_string(),
                FileOptions::default().method(Method::Stored),
            )
            .unwrap();
        }
        let z = w.finish().unwrap().into_inner();
        let d = directory(&z);
        assert!(d.zip64);
        assert_eq!(d.entries.len(), 70_000);
        assert_eq!(d.entries[69_999].name, b"69999");
        // One member fewer than the marker: no ZIP64 record.
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..65_534u32 {
            w.start_file(
                &i.to_string(),
                FileOptions::default().method(Method::Stored),
            )
            .unwrap();
        }
        let d = directory(&w.finish().unwrap().into_inner());
        assert!(!d.zip64);
        assert_eq!(d.entries.len(), 65_534);
    }

    /// The same records as for 4 GiB, with the thresholds lowered.
    #[test]
    fn sizes_and_offsets_past_the_limit_go_to_zip64_fields() {
        let stored = FileOptions::default().method(Method::Stored);
        let mut w = ZipWriter::new(Cursor::new(Vec::new())).with_thresholds(0xFFFF, 500);
        w.start_file("small", stored).unwrap();
        w.write_all(&[1u8; 100]).unwrap();
        w.start_file("reserved", stored.large_file(true)).unwrap();
        w.write_all(&[2u8; 100]).unwrap();
        w.start_file("past", stored.large_file(true)).unwrap();
        w.write_all(&[3u8; 700]).unwrap();
        w.start_file("deflated", FileOptions::default().large_file(true))
            .unwrap();
        w.write_all(&[4u8; 900]).unwrap();
        // Its offset is past the limit.
        w.start_file("after", stored).unwrap();
        w.write_all(b"end").unwrap();
        let z = w.finish().unwrap().into_inner();
        let d = directory(&z);
        assert!(d.zip64, "the directory starts past the limit");
        let sizes: Vec<(u64, u64)> = d.entries.iter().map(|e| (e.usize, e.csize)).collect();
        assert_eq!(sizes[..3], [(100, 100), (100, 100), (700, 700)]);
        assert_eq!(member(&z, &d.entries[1]), [2u8; 100]);
        assert_eq!(member(&z, &d.entries[2]), [3u8; 700]);
        assert_eq!(member(&z, &d.entries[3]), [4u8; 900]);
        assert!(d.entries[4].offset >= 500);
        assert_eq!(member(&z, &d.entries[4]), b"end");
        assert_eq!(d.entries[0].needed, 10);
        assert_eq!(d.entries[1].needed, 45);
        // A directory of three members or more is ZIP64 here.
        let mut w = ZipWriter::new(Cursor::new(Vec::new())).with_thresholds(3, 0xFFFF_FFFF);
        for n in ["a", "b", "c"] {
            w.start_file(n, stored).unwrap();
        }
        let d = directory(&w.finish().unwrap().into_inner());
        assert!(d.zip64);
        assert_eq!(d.entries.len(), 3);
    }

    #[test]
    fn a_member_past_the_limit_without_large_file_is_refused() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new())).with_thresholds(0xFFFF, 500);
        // Zeros deflate to a few bytes: the uncompressed size is what counts.
        w.start_file("a", FileOptions::default()).unwrap();
        let e = w.write_all(&[0u8; 501]).unwrap_err();
        assert!(e.to_string().contains("too large"), "{e}");
        // The compressed size counts too.
        let mut w = ZipWriter::new(Cursor::new(Vec::new())).with_thresholds(0xFFFF, 500);
        w.start_file("b", FileOptions::default().level(Some(0)))
            .unwrap();
        assert!(w.write_all(&[0u8; 499]).is_ok());
        assert!(w.finish().is_err());
    }

    /// The cipher of APPNOTE.TXT 6.1, written again here from the text.
    #[cfg(feature = "test-util")]
    fn decrypt(password: &[u8], body: &[u8]) -> Vec<u8> {
        fn crc_step(crc: u32, b: u8) -> u32 {
            let mut c = crc ^ u32::from(b);
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            c
        }
        let mut k = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
        fn update(k: &mut [u32; 3], b: u8) {
            k[0] = crc_step(k[0], b);
            k[1] = (k[1].wrapping_add(k[0] & 0xff))
                .wrapping_mul(134_775_813)
                .wrapping_add(1);
            k[2] = crc_step(k[2], (k[1] >> 24) as u8);
        }
        for &b in password {
            update(&mut k, b);
        }
        body.iter()
            .map(|&c| {
                let t = (k[2] | 2) as u16;
                let p = c ^ (t.wrapping_mul(t ^ 1) >> 8) as u8;
                update(&mut k, p);
                p
            })
            .collect()
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn a_zipcrypto_member_decrypts_with_its_password() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = FileOptions::default()
            .zipcrypto(b"secret")
            .modified(0x21, 0xAB00);
        w.start_file("locked", opts.method(Method::Stored)).unwrap();
        w.write_all(b"the body").unwrap();
        w.start_file("squeezed", opts).unwrap();
        w.write_all(&[9u8; 5000]).unwrap();
        w.start_file("open", FileOptions::default().method(Method::Stored))
            .unwrap();
        w.write_all(b"in the clear").unwrap();
        let z = w.finish().unwrap().into_inner();
        let d = directory(&z);
        let e = &d.entries[0];
        assert_eq!(e.flags, FLAG_ENCRYPTED | FLAG_DESCRIPTOR);
        assert_eq!((e.csize, e.usize), (12 + 8, 8));
        let start = e.offset as usize + 30 + e.name.len();
        let plain = decrypt(b"secret", &z[start..start + 20]);
        assert_eq!(plain[11], 0xAB, "the check byte is the time's high byte");
        assert_eq!(&plain[12..], b"the body");
        // The data descriptor follows the data.
        let dd = start + 20;
        assert_eq!(&z[dd..dd + 4], b"PK\x07\x08");
        assert_eq!(le(&z, dd + 4, 4) as u32, e.crc);
        assert_eq!((le(&z, dd + 8, 4), le(&z, dd + 12, 4)), (20, 8));
        let e = &d.entries[1];
        let start = e.offset as usize + 30 + e.name.len();
        let plain = decrypt(b"secret", &z[start..start + e.csize as usize]);
        let mut back = Vec::new();
        flate2::read::DeflateDecoder::new(&plain[12..])
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, [9u8; 5000]);
        assert_eq!(member(&z, &d.entries[2]), b"in the clear");
    }
}
