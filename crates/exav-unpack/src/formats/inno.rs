//! Inno Setup installers: the files of an installer whose data is in the
//! executable, Inno Setup 5.1.5 to 7.1.0.
//!
//! The layout is read as `innoextract` reads it (Daniel Scharrer, zlib
//! licence; attributed in `NOTICE`). Inno Setup's own source is not read.
//!
//! ```text
//! loader table   the executable's resource RCDATA 11111, as Setup finds it:
//!                where the setup headers (setup-0) and the file data
//!                (setup-1) start
//! setup-0        a 64-byte version string, from 6.5.0 a 53-byte encryption
//!                header, then two blocks: the setup header and its lists,
//!                and the data entries
//! block          CRC-32, stored size, compressed flag, then the data in
//!                4096-byte pieces each after its CRC-32, LZMA1 compressed
//! data entry     where a file is: its chunk (offset and size in setup-1),
//!                its offset and size in the chunk, flags
//! chunk          "zlb\x1a", then the files of the chunk one after the other,
//!                stored or compressed (zlib, bzip2, LZMA1 or LZMA2)
//! ```
//!
//! Of the first block, which holds the names and the scripts, only the start
//! of the setup header is read: the compression method every chunk uses, and
//! how many data entries the second block holds, which the size of that block
//! has to agree with. The rest is skipped: its layout changes with every
//! version, where the data entries' changes are few. A file is named by its
//! place in the entries. A file that went through the x86 call and jump
//! filter comes out with the filter undone.
//!
//! What is not read is reported, never passed as clean: an installer of a
//! version before 5.1.5 or past 7.1.0, one whose loader table or setup header
//! is not found, an encrypted file or encrypted setup headers
//! (`PASSWORD-PROTECTED`), a file in a separate `setup-N.bin`, and a file the
//! chunk ends before.

use std::io::{self, Read};

use crate::pe_resource::{LOADER_MAGICS, LOADER_RESOURCE, RT_RCDATA, resource_offsets};
use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_stream};
use crate::{Budget, LimitHit};

/// The bytes of the loader table, whose magic comes first, that are read: the
/// table of revision 2, the larger one.
const LOADER_TABLE_2: usize = 64;
const VERSION_STRING: usize = 64;
/// From 6.5.0, after the version string: a CRC-32, a byte saying whether the
/// installer is encrypted, and 48 bytes of key derivation data.
const ENCRYPTION_HEADER: usize = 53;
const CHUNK_MAGIC: &[u8; 4] = b"zlb\x1a";

const CALL_FILTER: u16 = 1 << 4;
const ENCRYPTED: u16 = 1 << 6;
const COMPRESSED: u16 = 1 << 7;

/// The installer's data version as `(major, minor, patch, revision)`: the
/// 6.4.0 release is `6.4.0.1`.
type Version = (u32, u32, u32, u32);

/// The first version read, and the first one past those read: innoextract
/// describes the layouts up to 7.0.2, whose data version is 7.0.0.3 (data
/// version 6.4.0.1 is the release of 6.4.0, and 6.4.1 writes it too; 6.5.4
/// writes 6.5.2, 6.6.x write 6.6.0 and 6.6.1, 6.7.x write 6.7.0). The 7.0.0
/// previews 1 to 3 write 6.7.0, 7.0.0.1 and 7.0.0.1, 7.0.0 beta to 7.0.2 and
/// 7.1.0 write 7.0.0.3, and 7.1.1 writes 7.1.1, which is past.
const FIRST: Version = (5, 1, 5, 0);
const PAST: Version = (7, 0, 0, 4);
/// Data versions between those two that innoextract has no layout for.
const UNDESCRIBED: [Version; 2] = [(7, 0, 0, 0), (7, 0, 0, 2)];

fn is_read(v: Version) -> bool {
    (FIRST..PAST).contains(&v) && !UNDESCRIBED.contains(&v)
}

/// The bytes between the version string and the setup header's block.
fn encryption_header(v: Version) -> usize {
    if v >= (6, 5, 0, 0) {
        ENCRYPTION_HEADER
    } else {
        0
    }
}

/// The bytes of a block's header: the CRC-32 of the rest, the stored size (8
/// bytes from 6.7.0, 4 before) and the compressed flag.
fn block_header(v: Version) -> usize {
    if v >= (6, 7, 0, 0) { 13 } else { 9 }
}

/// A block's stored size and its compressed flag, read from its header at
/// `at`. `None` when the source ends inside it.
fn block_head(src: &dyn ByteSource, at: usize, v: Version) -> Option<(u64, u8)> {
    let size = block_header(v) - 5;
    let h = src.window(at, block_header(v));
    let stored = if size == 8 {
        le64(&h, 4)?
    } else {
        u64::from(le32(&h, 4)?)
    };
    Some((stored, *h.get(4 + size)?))
}

/// An offset or a size, as far as the host's `usize` holds it.
fn to_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
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

/// The version in setup-0's version string, `Inno Setup Setup Data (5.5.7)`
/// and the like, with a suffix for the Unicode builds, and whether the
/// installer is a Unicode one (so are all from 6.3.0).
fn parse_version(s: &[u8]) -> Option<(Version, bool)> {
    const PREFIX: &[u8] = b"Inno Setup Setup Data (";
    let rest = s.strip_prefix(PREFIX)?;
    let end = rest.iter().position(|&b| b == b')')?;
    let text = std::str::from_utf8(&rest[..end]).ok()?;
    let mut parts = text.split('.').map(|p| p.parse::<u32>().ok());
    let v = (parts.next()??, parts.next()??, parts.next()??);
    let revision = parts.next().unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    let version = (v.0, v.1, v.2, revision);
    let suffix = &rest[end + 1..];
    let unicode =
        suffix.starts_with(b" (u)") || suffix.starts_with(b" (U)") || version >= (6, 3, 0, 0);
    Some((version, unicode))
}

/// The bytes of a data entry up to its checksum: the slices, the chunk
/// offset (4 bytes, 8 from 6.5.2), the file offset and size, the chunk size.
fn entry_base(v: Version) -> usize {
    if v >= (6, 5, 2, 0) { 40 } else { 36 }
}

/// Its checksum: MD5, SHA-1 from 5.3.9, SHA-256 from 6.4.0.
fn checksum_size(v: Version) -> usize {
    if v >= (6, 4, 0, 0) {
        32
    } else if v >= (5, 3, 9, 0) {
        20
    } else {
        16
    }
}

/// Where its flags are: after the checksum, the file time and the file
/// version.
fn flags_at(v: Version) -> usize {
    entry_base(v) + checksum_size(v) + 16
}

/// The bytes its flags take: one up to 5.1.12, two from 5.1.13, one again
/// from 6.4.3, which dropped four of the nine flags.
fn flags_size(v: Version) -> usize {
    if ((5, 1, 13, 0)..(6, 4, 3, 0)).contains(&v) {
        2
    } else {
        1
    }
}

/// The bytes of a data entry, which change with the version: the flags (see
/// [`flags_size`]), and a signing mode after them from 6.3.0 to 6.4.2.
fn entry_size(v: Version) -> usize {
    flags_at(v) + flags_size(v) + usize::from(((6, 3, 0, 0)..(6, 4, 3, 0)).contains(&v))
}

/// The flags read as the bits of [`CALL_FILTER`], [`ENCRYPTED`] and
/// [`COMPRESSED`]: from 6.4.3 they are the bits 2, 3 and 4.
fn flags_of(v: Version, raw: u16) -> u16 {
    if v < (6, 4, 3, 0) {
        return raw;
    }
    [(2, CALL_FILTER), (3, ENCRYPTED), (4, COMPRESSED)]
        .into_iter()
        .filter(|&(bit, _)| raw & (1 << bit) != 0)
        .fold(0, |flags, (_, flag)| flags | flag)
}

/// Where a file is.
#[derive(Clone, Debug)]
struct Entry {
    index: usize,
    first_slice: u32,
    last_slice: u32,
    chunk_offset: u64,
    file_offset: u64,
    file_size: u64,
    chunk_size: u64,
    flags: u16,
}

fn entries(data: &[u8], v: Version) -> Vec<Entry> {
    let at = flags_at(v);
    // The fields after the chunk offset move by the width it gained.
    let wide = entry_base(v) - 36;
    data.chunks_exact(entry_size(v))
        .enumerate()
        .filter_map(|(index, e)| {
            let flags = if flags_size(v) == 2 {
                u16::from_le_bytes([e[at], e[at + 1]])
            } else {
                u16::from(e[at])
            };
            let flags = flags_of(v, flags);
            Some(Entry {
                index,
                first_slice: le32(e, 0)?,
                last_slice: le32(e, 4)?,
                chunk_offset: if wide == 0 {
                    u64::from(le32(e, 8)?)
                } else {
                    le64(e, 8)?
                },
                file_offset: le64(e, 12 + wide)?,
                file_size: le64(e, 20 + wide)?,
                chunk_size: le64(e, 28 + wide)?,
                flags,
            })
        })
        .collect()
}

/// A block's data as it is read: its pieces' CRCs taken out and, when it is
/// compressed, decompressed. `None` when its header or its LZMA1 properties
/// cannot be read.
fn open_block(src: &dyn ByteSource, at: usize, v: Version, max: u64) -> Option<Box<dyn Read + '_>> {
    let (stored, compressed) = block_head(src, at, v)?;
    let start = at.saturating_add(block_header(v));
    let mut pieces = Pieces {
        inner: Reader::range(src, start, start.saturating_add(to_usize(stored))),
        left: 0,
    };
    if compressed == 0 {
        return Some(Box::new(pieces));
    }
    // LZMA1: the properties byte and the dictionary size, then the stream.
    let mut head = [0u8; 5];
    pieces.read_exact(&mut head).ok()?;
    let dict = crate::bounded_dict(le32(&head, 1)?, max);
    let lzma = lzma_rust2::LzmaStream::new_with_props(u64::MAX, head[0], dict, None).ok()?;
    Some(Box::new(super::lzma::SansIo::new(pieces, lzma)))
}

/// A block's data as it is stored: pieces of 4096 bytes, each after its CRC-32
/// (not checked).
struct Pieces<R> {
    inner: R,
    /// Bytes of the current piece not yet given; 0 where a CRC-32 is next.
    left: usize,
}

impl<R: Read> Read for Pieces<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut crc = [0u8; 4];
            let mut got = 0;
            while got < crc.len() {
                match self.inner.read(&mut crc[got..])? {
                    0 => return Ok(0),
                    n => got += n,
                }
            }
            self.left = 4096;
        }
        let want = buf.len().min(self.left);
        let n = self.inner.read(&mut buf[..want])?;
        self.left -= n;
        Ok(n)
    }
}

/// A block's data, its pieces' CRCs taken out, and decompressed when it is
/// compressed: at most `max` bytes, and whether it failed to decompress part
/// way. `Err` when it is over `max`; `None` when it cannot be read.
fn block(
    src: &dyn ByteSource,
    at: usize,
    v: Version,
    max: u64,
) -> Result<Option<(Vec<u8>, bool)>, LimitHit> {
    let Some((stored, _)) = block_head(src, at, v) else {
        return Ok(None);
    };
    if stored > max {
        return Err(LimitHit::new(format!(
            "Inno Setup header block is {stored} bytes, over the {max}-byte buffer \
             limit (--max-object-bytes): the installer's files were not scanned"
        )));
    }
    let Some(mut dec) = open_block(src, at, v, max) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    let got = crate::source::read_capped(&mut dec, &mut out, max.saturating_add(1));
    if out.len() as u64 > max {
        return Err(LimitHit::new(format!(
            "Inno Setup header block decompresses past the {max}-byte buffer \
             limit (--max-object-bytes): the installer's files were not scanned"
        )));
    }
    // A block that fails part way gives the entries before the failure, and
    // says so. One that ends without an end marker is whole.
    let damaged = got.is_err_and(|e| e.kind() != io::ErrorKind::UnexpectedEof);
    Ok(Some((out, damaged)))
}

const SETUP_ENCRYPTED: &str = "Inno Setup installer with encrypted setup data, which needs its \
     password: the files it installs were not examined";

/// One report for the whole installer. `encrypted` when its setup data is
/// encrypted: `reason` is then not used.
fn report(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
    reason: &'static str,
    encrypted: bool,
) -> Result<Option<()>, LimitHit> {
    budget.count_entry()?;
    let meta = MemberMeta {
        name: "inno-setup-payload".to_string(),
        comp_size: src.len() as u64,
        encrypted,
        unsupported: Some(if encrypted { SETUP_ENCRYPTED } else { reason }),
        ..MemberMeta::default()
    };
    Ok(visit(&meta, None, budget))
}

/// The loader table: where setup-0 and setup-1 start. Setup reads it from
/// the executable's resource, so that is where it is looked for; a stub with
/// the resource in more than one language gives one table, or none.
fn loader(src: &dyn ByteSource) -> Option<(usize, usize)> {
    let mut found = None;
    for at in resource_offsets(&|off, len| src.window(off, len), RT_RCDATA, LOADER_RESOURCE)? {
        let t = src.window(at, LOADER_TABLE_2);
        if !LOADER_MAGICS.iter().any(|m| t.starts_with(&m[..])) {
            return None;
        }
        // Revision 2 has 64-bit offsets, in a table of 64 bytes where
        // revision 1 has 44. Another revision is read as revision 1, as
        // innoextract does.
        let pair = if le32(&t, 12)? == 2 {
            (
                usize::try_from(le64(&t, 40)?).ok()?,
                usize::try_from(le64(&t, 48)?).ok()?,
            )
        } else {
            (le32(&t, 32)? as usize, le32(&t, 36)? as usize)
        };
        if found.is_some_and(|f| f != pair) {
            return None;
        }
        found = Some(pair);
    }
    found
}

/// How the chunks are compressed, as the setup header says.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Method {
    Stored,
    Zlib,
    Bzip2,
    Lzma1,
    Lzma2,
}

/// The compression the setup header names with `byte`: LZMA2 is known from
/// 5.3.9.
fn method(v: Version, byte: u8) -> Option<Method> {
    Some(match byte {
        0 => Method::Stored,
        1 => Method::Zlib,
        2 => Method::Bzip2,
        3 => Method::Lzma1,
        4 if v >= (5, 3, 9, 0) => Method::Lzma2,
        _ => return None,
    })
}

/// Skip `n` bytes of `r`; `None` where it ends first.
fn skip(r: &mut impl Read, n: u64) -> Option<()> {
    let got = io::copy(&mut r.by_ref().take(n), &mut io::sink()).ok()?;
    (got == n).then_some(())
}

fn read_u32(r: &mut impl Read) -> Option<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// The start of the setup header, as the version lays it out: the compression
/// the chunks use and the number of data entries, the fields of it that are
/// read. The strings and the numbers before them are skipped.
fn header_fields(r: &mut impl Read, v: Version, unicode: bool) -> Option<(Method, u32)> {
    let n = |c: bool| usize::from(c);
    // The strings, each a length and its bytes: the application's names, urls
    // and mutexes, the texts of the wizard, and the compiled script.
    let strings = 6
        + n(v >= (5, 1, 13, 0))
        + 3
        + 2
        + 1
        + 3 * n(v < (5, 2, 5, 0))
        + 1
        + 2
        + 1
        + 2
        + 1
        + n(v < (5, 2, 5, 0))
        + 4
        + n(v >= (5, 3, 8, 0))
        + n(v >= (5, 3, 10, 0))
        + n(v >= (5, 5, 0, 0))
        + n(v >= (5, 5, 6, 0))
        + 2 * n(v >= (5, 6, 1, 0))
        + 2 * n(v >= (6, 3, 0, 0))
        + n(v >= (6, 4, 2, 0))
        + n(v >= (6, 5, 0, 0))
        + 5 * n(v >= (6, 7, 0, 0))
        + 3 * n(v >= (5, 2, 5, 0))
        + n(((5, 2, 1, 0)..(5, 3, 10, 0)).contains(&v))
        + n(v >= (5, 2, 5, 0));
    for _ in 0..strings {
        let len = read_u32(r)?;
        skip(r, u64::from(len))?;
    }
    // The characters that start a two-byte character, in a build that is not
    // Unicode.
    if !unicode {
        skip(r, 32)?;
    }
    // The counts of languages, messages, permissions, types, components and
    // tasks, then those of directories, from 6.5.0 of signing keys, and of
    // files, the data entries, and the seven kinds that follow.
    skip(r, 6 * 4 + 4 + 4 * n(v >= (6, 5, 0, 0)) as u64 + 4)?;
    let entries = read_u32(r)?;
    skip(r, 7 * 4)?;
    // From 7.0.0.3 the version of the compiled script.
    skip(r, 4 * n(v >= (7, 0, 0, 3)) as u64)?;
    // The Windows versions it runs on.
    skip(r, 20)?;
    let mut fixed = 0u64;
    // Colours of the wizard, up to 6.4.0 (revision 1).
    fixed += 8 * n(v < (6, 4, 0, 1)) as u64;
    fixed += 4 * n(v < (5, 5, 7, 0)) as u64;
    // Its style and how it resizes (from 6.6.0 its dark style, in another
    // order), then the alpha format of its images.
    fixed += 9 * n(v >= (6, 0, 0, 0)) as u64;
    fixed += n(v >= (5, 5, 7, 0)) as u64;
    // The colours of the wizard's images, back in the header from 6.5.2.
    fixed += 8 * n(v >= (6, 5, 2, 0)) as u64;
    // Those of the dark theme from 6.6.0, and from 6.6.1 the images' opacity.
    fixed += 8 * n(v >= (6, 6, 0, 0)) as u64;
    fixed += n(v >= (6, 6, 1, 0)) as u64;
    // From 6.7.0 the colour of the wizard's background and its dark one, then
    // the opacity of its background image and the light control styling
    // (a byte each).
    fixed += (4 + 4 + 1 + 1) * n(v >= (6, 7, 0, 0)) as u64;
    // The password's hash and salt, which 6.5.0 moved to the encryption
    // header.
    fixed += if v >= (6, 5, 0, 0) {
        0
    } else if v >= (6, 4, 0, 0) {
        4 + 44
    } else if v >= (5, 3, 9, 0) {
        20 + 8
    } else {
        16 + 8
    };
    // Disk space and slices per disk; the log mode, the warning for an
    // existing directory and the privileges; what overrides them; the
    // dialog for the language and how it is detected.
    fixed += 8 + 4 + 3;
    fixed += n(v >= (5, 7, 0, 0)) as u64;
    fixed += 2;
    skip(r, fixed)?;
    let mut byte = [0u8; 1];
    r.read_exact(&mut byte).ok()?;
    Some((method(v, byte[0])?, entries))
}

/// The decoder of a chunk's data, `size` bytes at `at`, decoding at most
/// `out` bytes.
fn decoder<'a>(
    src: &'a dyn ByteSource,
    at: usize,
    size: usize,
    m: Method,
    out: u64,
) -> Option<Box<dyn Read + 'a>> {
    let raw = Reader::range(src, at, at.saturating_add(size));
    Some(match m {
        Method::Stored => Box::new(raw),
        Method::Zlib => Box::new(flate2::read::ZlibDecoder::new(raw)),
        Method::Bzip2 => Box::new(super::bzip2_rs::DecoderReader::new(raw)),
        Method::Lzma1 => {
            let head = src.window(at, 5);
            let (&props, dict) = (head.first()?, le32(&head, 1)?);
            let dict = crate::bounded_dict(dict, out);
            let lzma = lzma_rust2::LzmaStream::new_with_props(u64::MAX, props, dict, None).ok()?;
            let raw = Reader::range(src, at.saturating_add(5), at.saturating_add(size));
            Box::new(super::lzma::SansIo::new(raw, lzma))
        }
        Method::Lzma2 => {
            let prop = *src.window(at, 1).first()?;
            if prop > 40 {
                return None;
            }
            let dict = if prop == 40 {
                u32::MAX
            } else {
                (2 | u32::from(prop & 1)) << (prop / 2 + 11)
            };
            let lzma2 = lzma_rust2::Lzma2Stream::new(crate::bounded_dict(dict, out));
            let raw = Reader::range(src, at.saturating_add(1), at.saturating_add(size));
            Box::new(super::lzma::SansIo::new(raw, lzma2))
        }
    })
}

/// Undoes Inno's x86 call and jump filter on one file, as it is read.
enum Filter {
    /// Up to 5.1.x.
    V4108 { addr: u32, left: u8, offset: u32 },
    /// From 5.2.0, the high byte flipped from 5.3.9.
    V5200 { flip: bool, offset: u32 },
}

impl Filter {
    fn new(version: Version) -> Self {
        if version < (5, 2, 0, 0) {
            Filter::V4108 {
                addr: 0,
                left: 0,
                offset: 5,
            }
        } else {
            Filter::V5200 {
                flip: version >= (5, 3, 9, 0),
                offset: 0,
            }
        }
    }

    /// Undo the filter on `input`, appending to `out`, and return how much of
    /// `input` was taken: all of it but a call or jump whose four address
    /// bytes are not all there, unless the input has ended.
    fn run(&mut self, input: &[u8], ended: bool, out: &mut Vec<u8>) -> usize {
        match self {
            Filter::V4108 { addr, left, offset } => {
                for &b in input {
                    let mut b = b;
                    if *left == 0 {
                        if b == 0xe8 || b == 0xe9 {
                            *addr = (!*offset).wrapping_add(1);
                            *left = 4;
                        }
                    } else {
                        *addr = addr.wrapping_add(u32::from(b));
                        b = *addr as u8;
                        *addr >>= 8;
                        *left -= 1;
                    }
                    *offset = offset.wrapping_add(1);
                    out.push(b);
                }
                input.len()
            }
            Filter::V5200 { flip, offset } => {
                let mut i = 0;
                while i < input.len() {
                    let b = input[i];
                    let block_left = 0x10000 - (*offset % 0x10000);
                    if (b == 0xe8 || b == 0xe9) && block_left >= 5 && input.len() - i < 5 && !ended
                    {
                        break;
                    }
                    out.push(b);
                    *offset = offset.wrapping_add(1);
                    i += 1;
                    if (b != 0xe8 && b != 0xe9) || block_left < 5 || input.len() - i < 4 {
                        continue;
                    }
                    let mut a = [input[i], input[i + 1], input[i + 2], input[i + 3]];
                    *offset = offset.wrapping_add(4);
                    i += 4;
                    if a[3] == 0 || a[3] == 0xff {
                        let addr = *offset & 0xff_ffff;
                        let rel = (u32::from(a[0]) | u32::from(a[1]) << 8 | u32::from(a[2]) << 16)
                            .wrapping_sub(addr);
                        a[0] = rel as u8;
                        a[1] = (rel >> 8) as u8;
                        a[2] = (rel >> 16) as u8;
                        if *flip && rel & 0x80_0000 != 0 {
                            a[3] = !a[3];
                        }
                    }
                    out.extend_from_slice(&a);
                }
                i
            }
        }
    }
}

/// A file read through [`Filter`].
struct Filtered<R> {
    inner: R,
    filter: Filter,
    /// Input not yet taken by the filter.
    carry: Vec<u8>,
    out: Vec<u8>,
    at: usize,
    ended: bool,
}

impl<R: Read> Read for Filtered<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at == self.out.len() {
            if self.ended && self.carry.is_empty() {
                return Ok(0);
            }
            self.out.clear();
            self.at = 0;
            let mut more = [0u8; 8192];
            let n = self.inner.read(&mut more)?;
            self.ended = n == 0;
            self.carry.extend_from_slice(&more[..n]);
            let taken = self.filter.run(&self.carry, self.ended, &mut self.out);
            self.carry.drain(..taken);
        }
        let n = buf.len().min(self.out.len() - self.at);
        buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// A file's bytes, an error where the chunk ends before the file does: the
/// file was not read in full.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::other(
                "Inno Setup chunk ended before the file it holds",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Counts what is read through it.
struct Counted<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        Ok(n)
    }
}

/// The setup header, the first block at `at`: how its chunks are compressed
/// and how many data entries follow. `None` when it is not laid out as
/// `version` says; `Err` when reading as far as that takes more than the
/// buffer limit.
fn header_block(
    src: &dyn ByteSource,
    at: usize,
    version: Version,
    unicode: bool,
    budget: &mut Budget,
) -> Result<Option<(Method, u32)>, LimitHit> {
    let max = budget.limits().max_buffer_bytes;
    let Some(block) = open_block(src, at, version, max) else {
        return Ok(None);
    };
    let mut r = block.take(max);
    let found = header_fields(&mut r, version, unicode);
    // The decoding up to the fields is work like scanning.
    budget.charge_scan(max - r.limit())?;
    if found.is_none() && r.limit() == 0 {
        return Err(LimitHit::new(format!(
            "Inno Setup header fields are past the first {max} bytes of its block, \
             over the buffer limit (--max-object-bytes): the installer's files were \
             not scanned"
        )));
    }
    Ok(found)
}

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let head = src.window(0, 2);
    if !head.starts_with(b"MZ") {
        return Ok(None);
    }
    let Some((setup0, setup1)) = loader(src) else {
        if crate::pe_resource::has_old_inno_loader(&|off, len| src.window(off, len)) {
            return report(
                src,
                budget,
                visit,
                "Inno Setup installer of a version before 5.1.5, which exav does not \
                 read: the files it installs were not examined",
                false,
            );
        }
        return report(
            src,
            budget,
            visit,
            "Inno Setup installer whose loader table exav does not find (a version \
             before 5.1.5, or a damaged file): \
             the files it installs were not examined",
            false,
        );
    };
    let Some((version, unicode)) = parse_version(&src.window(setup0, VERSION_STRING)) else {
        return report(
            src,
            budget,
            visit,
            "Inno Setup installer whose setup data exav does not recognise: the \
             files it installs were not examined",
            false,
        );
    };
    if !is_read(version) {
        return report(
            src,
            budget,
            visit,
            "Inno Setup installer of a version exav does not read: the files it \
             installs were not examined",
            false,
        );
    }
    let max = budget.limits().max_buffer_bytes;
    let after_version = setup0.saturating_add(VERSION_STRING);
    // The byte of the encryption header that says whether the installer is
    // encrypted: 0 when it is not.
    let encryption = encryption_header(version);
    let in_use = if encryption == 0 {
        Some(false)
    } else {
        let h = src.window(after_version, encryption);
        (h.len() == encryption).then(|| h[4] != 0)
    };
    let first = after_version.saturating_add(encryption);
    let Some((in_use, (first_stored, compressed))) = in_use.zip(block_head(src, first, version))
    else {
        return report(
            src,
            budget,
            visit,
            "Inno Setup installer cut short in its setup header: the files it \
             installs were not examined",
            false,
        );
    };
    // With the setup headers encrypted too, there is no block to read.
    if in_use && compressed > 1 {
        return report(src, budget, visit, SETUP_ENCRYPTED, true);
    }
    let second = first
        .saturating_add(block_header(version))
        .saturating_add(to_usize(first_stored));
    let Some((data, damaged)) = block(src, second, version, max)? else {
        return report(
            src,
            budget,
            visit,
            "Inno Setup installer whose file table could not be read: the files \
             it installs were not examined",
            in_use,
        );
    };
    // The chunks are decoded as the setup header says, which also counts the
    // data entries: a header that is not laid out as the version says, or
    // counts others than the block holds, is not read.
    let header = header_block(src, first, version, unicode, budget)?;
    let size = entry_size(version);
    let held = (data.len() / size) as u64;
    let whole = data.len() % size == 0;
    let counted = |count: u32| {
        let count = u64::from(count);
        // A table damaged part way holds fewer than the header counts.
        if damaged {
            count >= held
        } else {
            whole && count == held
        }
    };
    let Some(method) = header.filter(|&(_, count)| counted(count)).map(|(m, _)| m) else {
        return report(
            src,
            budget,
            visit,
            "Inno Setup installer whose setup header exav does not recognise: the \
             files it installs were not examined",
            in_use,
        );
    };
    if damaged
        && let Some(t) = report(
            src,
            budget,
            visit,
            "Inno Setup installer whose file table is damaged part way: the files \
             past the damage were not examined",
            false,
        )?
    {
        return Ok(Some(t));
    }
    let mut list = entries(&data, version);
    // A chunk is told by where it lies, its size and how it is stored.
    let chunk_of = |e: &Entry| {
        (
            e.first_slice,
            e.last_slice,
            e.chunk_offset,
            e.chunk_size,
            e.flags & (COMPRESSED | ENCRYPTED),
        )
    };
    list.sort_by_key(|e| (chunk_of(e), e.file_offset, e.index));
    let mut i = 0;
    while i < list.len() {
        let chunk = chunk_of(&list[i]);
        let end = list[i..]
            .iter()
            .position(|e| chunk_of(e) != chunk)
            .map_or(list.len(), |n| i + n);
        if let Some(t) = walk_chunk(src, setup1, version, method, &list[i..end], budget, visit)? {
            return Ok(Some(t));
        }
        i = end;
    }
    Ok(None)
}

fn name(e: &Entry) -> String {
    format!("inno-file-{}", e.index)
}

/// The files of one chunk, in the order they lie in it.
fn walk_chunk(
    src: &dyn ByteSource,
    setup1: usize,
    version: Version,
    method: Method,
    files: &[Entry],
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    let first = &files[0];
    let unread = |e: &Entry, reason: &'static str, encrypted: bool| MemberMeta {
        name: name(e),
        comp_size: e.chunk_size,
        size: Some(e.file_size),
        encrypted,
        unsupported: Some(reason),
        ..MemberMeta::default()
    };
    let reason: Option<(&'static str, bool)> = if first.flags & ENCRYPTED != 0 {
        Some((
            "Inno Setup file encrypted with the installer's password: not examined",
            true,
        ))
    } else if setup1 == 0 || first.first_slice != 0 || first.last_slice != 0 {
        Some((
            "Inno Setup file stored in a separate setup data file (setup-1.bin): \
             not examined",
            false,
        ))
    } else {
        None
    };
    let at = setup1.saturating_add(usize::try_from(first.chunk_offset).unwrap_or(usize::MAX));
    let magic_ok = src.window(at, 4).as_ref() == CHUNK_MAGIC;
    let data_at = at.saturating_add(4);
    let reason = reason.or((!magic_ok).then_some((
        "Inno Setup chunk not found where its entry places it: not examined",
        false,
    )));
    if let Some((reason, encrypted)) = reason {
        for e in files {
            budget.count_entry()?;
            if let Some(t) = visit(&unread(e, reason, encrypted), None, budget) {
                return Ok(Some(t));
            }
        }
        return Ok(None);
    }
    // A file the setup header says is not compressed is stored whatever the
    // method is.
    let m = if first.flags & COMPRESSED != 0 {
        method
    } else {
        Method::Stored
    };
    // The dictionary is allocated before a byte is decoded: no larger than
    // what the chunk's files need, nor than the buffer limit.
    let out = files
        .iter()
        .map(|e| e.file_offset.saturating_add(e.file_size))
        .max()
        .unwrap_or(0)
        .min(budget.limits().max_buffer_bytes);
    let size = usize::try_from(first.chunk_size).unwrap_or(usize::MAX);
    let open = || decoder(src, data_at, size, m, out).map(|d| Counted { inner: d, n: 0 });
    let mut dec = open();
    for e in files {
        budget.count_entry()?;
        let Some(d) = dec.as_mut().filter(|d| d.n <= e.file_offset) else {
            // A file before the decoder's place (one that shares another's
            // data): the chunk again from its start.
            dec = open();
            let Some(d) = dec.as_mut() else {
                let meta = unread(
                    e,
                    "Inno Setup chunk could not be decoded: not examined",
                    false,
                );
                if let Some(t) = visit(&meta, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            };
            if let Some(t) = file(d, e, version, budget, visit)? {
                return Ok(Some(t));
            }
            continue;
        };
        if let Some(t) = file(d, e, version, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// One file of a chunk, from where the decoder is.
fn file(
    d: &mut Counted<Box<dyn Read + '_>>,
    e: &Entry,
    version: Version,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    // Decoding up to the file is work like scanning: it is charged to the scan
    // budget, so that entries that send the walk back over a chunk again and
    // again are bounded.
    let skip = e.file_offset - d.n;
    budget.charge_scan(skip)?;
    let skipped = io::copy(&mut (&mut *d).take(skip), &mut io::sink());
    let mut meta = MemberMeta {
        name: name(e),
        comp_size: e.file_size,
        size: Some(e.file_size),
        ..MemberMeta::default()
    };
    if !matches!(skipped, Ok(n) if n == skip) {
        meta.unsupported = Some("Inno Setup chunk ended or failed before this file: not examined");
        return Ok(visit(&meta, None, budget));
    }
    let body = Exact {
        inner: &mut *d,
        left: e.file_size,
    };
    if e.flags & CALL_FILTER == 0 {
        let mut body = body;
        return emit_stream(&meta, &mut body, budget, visit);
    }
    let mut body = Filtered {
        inner: body,
        filter: Filter::new(version),
        carry: Vec::new(),
        out: Vec::new(),
        at: 0,
        ended: false,
    };
    emit_stream(&meta, &mut body, budget, visit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Limits, Member};
    use std::io::Write;

    /// One file of an installer the tests build.
    struct Spec<'a> {
        data: &'a [u8],
        method: Method,
        filtered: bool,
        flags: u16,
        /// Bytes the chunk's size, as its entry gives it, falls short of.
        cut: u64,
    }

    fn spec(data: &[u8], method: Method) -> Spec<'_> {
        Spec {
            data,
            method,
            filtered: false,
            flags: 0,
            cut: 0,
        }
    }

    /// LZMA1 as Inno writes it, with `pb` position bits: the properties byte
    /// is 3 for 0, which is also a valid first byte of an LZMA2 stream.
    fn lzma1(data: &[u8], pb: u32) -> Vec<u8> {
        let mut opts = lzma_rust2::LzmaOptions::with_preset(6);
        opts.pb = pb;
        let mut out = vec![0u8; 5];
        let mut w = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, true).unwrap();
        out[0] = w.props();
        out[1..5].copy_from_slice(&opts.dict_size.to_le_bytes());
        w.write_all(data).unwrap();
        out.extend(w.finish().unwrap());
        out
    }

    fn compress(data: &[u8], m: Method) -> Vec<u8> {
        match m {
            Method::Stored => data.to_vec(),
            Method::Zlib => {
                let mut e =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Method::Bzip2 => {
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Method::Lzma1 => lzma1(data, 2),
            Method::Lzma2 => {
                let opts = lzma_rust2::Lzma2Options::with_preset(6);
                // Dictionary property 16: 2^19 bytes.
                let mut out = vec![16u8];
                let mut w = lzma_rust2::Lzma2Writer::new(Vec::new(), opts);
                w.write_all(data).unwrap();
                out.extend(w.finish().unwrap());
                out
            }
        }
    }

    /// The x86 filter as the compiler applies it, from 5.2.0, written apart
    /// from the decoder.
    fn x86_encode(data: &[u8], flip: bool) -> Vec<u8> {
        let mut out = data.to_vec();
        let mut i = 0usize;
        while i < out.len() {
            let b = out[i];
            let block_left = 0x10000 - (i % 0x10000);
            i += 1;
            if (b != 0xe8 && b != 0xe9) || block_left < 5 || out.len() - i < 4 {
                continue;
            }
            let addr = ((i + 4) & 0xff_ffff) as u32;
            let o = [out[i], out[i + 1], out[i + 2], out[i + 3]];
            let rel = u32::from(o[0]) | u32::from(o[1]) << 8 | u32::from(o[2]) << 16;
            let a3 = if flip && rel & 0x80_0000 != 0 {
                !o[3]
            } else {
                o[3]
            };
            if a3 == 0 || a3 == 0xff {
                let s = rel.wrapping_add(addr);
                out[i] = s as u8;
                out[i + 1] = (s >> 8) as u8;
                out[i + 2] = (s >> 16) as u8;
                out[i + 3] = a3;
            }
            i += 4;
        }
        out
    }

    /// A block of setup-0: its header (the stored size has 8 bytes from
    /// 6.7.0, 4 before), then the data in pieces of 4096 bytes, each after a
    /// CRC-32 (not checked, so zero here).
    fn block(v: Version, data: &[u8], compressed: bool) -> Vec<u8> {
        let mut raw = Vec::new();
        for piece in data.chunks(4096) {
            raw.extend_from_slice(&[0; 4]);
            raw.extend_from_slice(piece);
        }
        let mut out = vec![0u8; 4];
        if v >= (6, 7, 0, 0) {
            out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        } else {
            out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        }
        out.push(u8::from(compressed));
        out.extend(raw);
        out
    }

    /// An installer of version `v` whose data is in the executable: each
    /// file in a chunk of its own, or all in one chunk of the first file's
    /// method when `solid`.
    fn build(v: Version, files: &[Spec], solid: bool) -> Vec<u8> {
        build_repeating(v, files, solid, 0)
    }

    /// [`build`], with the last data entry repeated `repeat` times more.
    fn build_repeating(v: Version, files: &[Spec], solid: bool, repeat: usize) -> Vec<u8> {
        Setup::new(v).repeating(repeat).build(files, solid)
    }

    /// Where the loader table is in the stub: the data of its resource.
    const LOADER_AT: usize = 0x270;

    /// The setup stub: a PE file of one section, `.rsrc`, whose resource
    /// RCDATA 11111 is the loader table (44 bytes at [`LOADER_AT`], to fill),
    /// laid out as Windows reads it and padded to 0x400 bytes.
    fn stub() -> Vec<u8> {
        let mut s = vec![0u8; 0x400];
        let mut put = |at: usize, v: &[u8]| s[at..at + v.len()].copy_from_slice(v);
        put(0, b"MZ");
        put(0x3c, &0x40u32.to_le_bytes());
        put(0x40, b"PE\0\0");
        // COFF: one section, 224 bytes of optional header.
        put(0x46, &1u16.to_le_bytes());
        put(0x54, &0xe0u16.to_le_bytes());
        // PE32: the count of data directories, and the third, resources.
        put(0x58, &0x10bu16.to_le_bytes());
        put(0x58 + 92, &16u32.to_le_bytes());
        put(0xb8 + 16, &0x1000u32.to_le_bytes());
        put(0xb8 + 20, &0x200u32.to_le_bytes());
        // The section: at 0x1000 in memory, 0x200 in the file.
        put(0x138, b".rsrc\0\0\0");
        put(0x138 + 8, &0x200u32.to_le_bytes());
        put(0x138 + 12, &0x1000u32.to_le_bytes());
        put(0x138 + 16, &0x200u32.to_le_bytes());
        put(0x138 + 20, &0x200u32.to_le_bytes());
        // Three directories of one entry (type, name, language), then the
        // data entry: addresses are relative to the first. The directory of
        // languages has room for a second entry, and a second data entry
        // follows the first.
        let sub = 0x8000_0000u32;
        for (dir, id, target) in [
            (0x200, 10u32, sub | 0x18),
            (0x218, 11111, sub | 0x30),
            (0x230, 0x409, 0x50),
        ] {
            put(dir + 14, &1u16.to_le_bytes());
            put(dir + 16, &id.to_le_bytes());
            put(dir + 20, &target.to_le_bytes());
        }
        put(0x248, &0x40au32.to_le_bytes());
        put(0x24c, &0x60u32.to_le_bytes());
        for leaf in [0x250, 0x260] {
            put(
                leaf,
                &(0x1000u32 + (LOADER_AT - 0x200) as u32).to_le_bytes(),
            );
            put(leaf + 4, &44u32.to_le_bytes());
        }
        s
    }

    /// The numbers of a setup header up to its compression method, as `v`
    /// has them, with `entries` data entries and then some of what follows.
    /// Written field by field, apart from the reader.
    fn header_start(v: Version, unicode: bool, method: u8, entries: u32) -> Vec<u8> {
        let mut h = Vec::new();
        let ge = |a: Version| v >= a;
        let strings = |h: &mut Vec<u8>, lens: &[usize]| {
            for &n in lens {
                h.extend_from_slice(&(n as u32).to_le_bytes());
                h.extend(std::iter::repeat_n(b'x', n));
            }
        };
        // Name, versioned name, id, copyright, publisher and its address.
        strings(&mut h, &[5, 0, 3, 7, 9, 2]);
        if ge((5, 1, 13, 0)) {
            strings(&mut h, &[4]);
        }
        // Support and update addresses, version, directory, group, base name.
        strings(&mut h, &[1, 8, 0, 6, 0, 12]);
        if v < (5, 2, 5, 0) {
            // License, text before and after.
            strings(&mut h, &[9000, 2, 0]);
        }
        // Uninstall directory, name and icon, mutex, user, organisation, serial.
        strings(&mut h, &[3, 4, 5, 0, 0, 0, 0]);
        if v < (5, 2, 5, 0) {
            strings(&mut h, &[40]);
        }
        strings(&mut h, &[2, 0, 1, 3]);
        if ge((5, 3, 8, 0)) {
            strings(&mut h, &[6]);
        }
        if ge((5, 3, 10, 0)) {
            strings(&mut h, &[2]);
        }
        if ge((5, 5, 0, 0)) {
            strings(&mut h, &[7]);
        }
        if ge((5, 5, 6, 0)) {
            strings(&mut h, &[3]);
        }
        if ge((5, 6, 1, 0)) {
            strings(&mut h, &[0, 2]);
        }
        if ge((6, 3, 0, 0)) {
            strings(&mut h, &[4, 5]);
        }
        if ge((6, 4, 2, 0)) {
            // The filter of the applications to close, its exclusions.
            strings(&mut h, &[7]);
        }
        if ge((6, 5, 0, 0)) {
            // The name of the 7-Zip library.
            strings(&mut h, &[11]);
        }
        if ge((6, 7, 0, 0)) {
            // The expressions of the five "use previous" settings.
            strings(&mut h, &[2, 0, 5, 1, 3]);
        }
        if ge((5, 2, 5, 0)) {
            strings(&mut h, &[5000, 1, 0]);
        }
        if ge((5, 2, 1, 0)) && v < (5, 3, 10, 0) {
            strings(&mut h, &[8]);
        }
        if ge((5, 2, 5, 0)) {
            strings(&mut h, &[60]);
        }
        if !unicode {
            h.extend_from_slice(&[0xaa; 32]);
        }
        let words = |h: &mut Vec<u8>, w: &[u32]| {
            for x in w {
                h.extend_from_slice(&x.to_le_bytes());
            }
        };
        // Languages, messages, permissions, types, components, tasks,
        // directories, signing keys (from 6.5.0), files, data entries, and
        // seven more kinds.
        words(&mut h, &[1, 2, 3, 4, 5, 6, 7]);
        if ge((6, 5, 0, 0)) {
            words(&mut h, &[99]);
        }
        words(&mut h, &[8, entries, 9, 10, 11, 12, 13, 14, 15]);
        if ge((7, 0, 0, 3)) {
            // The version of the compiled script.
            words(&mut h, &[0xc0de]);
        }
        h.extend_from_slice(&[0x55; 20]);
        if v < (6, 4, 0, 1) {
            h.extend_from_slice(&[0x11; 8]);
        }
        if v < (5, 5, 7, 0) {
            h.extend_from_slice(&[0x22; 4]);
        }
        if ge((6, 0, 0, 0)) {
            h.extend_from_slice(&[0x33; 9]);
        }
        if ge((5, 5, 7, 0)) {
            h.push(0x44);
        }
        if ge((6, 5, 2, 0)) {
            h.extend_from_slice(&[0x45; 8]);
        }
        if ge((6, 7, 0, 0)) {
            h.extend_from_slice(&[0x4c; 4]);
        }
        if ge((6, 6, 0, 0)) {
            h.extend_from_slice(&[0x46; 8]);
        }
        if ge((6, 7, 0, 0)) {
            h.extend_from_slice(&[0x4d; 4]);
        }
        if ge((6, 6, 1, 0)) {
            h.push(0x47);
        }
        if ge((6, 7, 0, 0)) {
            h.extend_from_slice(&[0x48, 0x49]);
        }
        let password = if ge((6, 5, 0, 0)) {
            0
        } else if ge((6, 4, 0, 0)) {
            4 + 44
        } else if ge((5, 3, 9, 0)) {
            20 + 8
        } else {
            16 + 8
        };
        h.extend(std::iter::repeat_n(0x66, password));
        // Disk space and slices; log mode, directory warning, privileges.
        h.extend_from_slice(&[0x77; 12 + 3]);
        if ge((5, 7, 0, 0)) {
            h.push(0x88);
        }
        h.extend_from_slice(&[0x99; 2]);
        h.push(method);
        // Flags and the rest of the header, more than a piece of a block.
        h.extend_from_slice(&[0xee; 5000]);
        h
    }

    /// An installer the tests build, with what can be made to differ.
    struct Setup {
        v: Version,
        unicode: bool,
        repeat: usize,
        lzma_pb: u32,
        /// The method byte of the header, when it is not the files'.
        header_method: Option<u8>,
        /// Data entries the header counts, when not those there are.
        counted: Option<u32>,
        /// A second loader table in the stub, outside its resources.
        decoy: bool,
        /// The loader table of revision 2, with 64-bit offsets.
        table2: bool,
        /// The upper 32 bits of every chunk offset (from 6.5.2).
        chunk_high: u64,
        /// The encryption header's byte (from 6.5.0), and whether the setup
        /// headers are then unreadable.
        encryption: u8,
        scrambled: bool,
    }

    impl Setup {
        fn new(v: Version) -> Self {
            Setup {
                v,
                unicode: v >= (5, 3, 9, 0),
                repeat: 0,
                lzma_pb: 2,
                header_method: None,
                counted: None,
                decoy: false,
                table2: false,
                chunk_high: 0,
                encryption: 0,
                scrambled: false,
            }
        }

        fn repeating(mut self, repeat: usize) -> Self {
            self.repeat = repeat;
            self
        }

        fn build(&self, files: &[Spec], solid: bool) -> Vec<u8> {
            let (v, repeat) = (self.v, self.repeat);
            let compress = |data: &[u8], m: Method| match m {
                Method::Lzma1 => lzma1(data, self.lzma_pb),
                m => compress(data, m),
            };
            let mut exe = stub();
            // setup-1: the chunks.
            let setup1 = exe.len();
            let mut entries = Vec::new();
            let mut chunk_data = Vec::new();
            let mut placed = Vec::new();
            for (i, f) in files.iter().enumerate() {
                let content = if f.filtered {
                    x86_encode(f.data, v >= (5, 3, 9, 0))
                } else {
                    f.data.to_vec()
                };
                if solid {
                    placed.push((0u32, chunk_data.len() as u64));
                    chunk_data.extend_from_slice(&content);
                    if i + 1 < files.len() {
                        continue;
                    }
                    let z = compress(&chunk_data, files[0].method);
                    let off = (exe.len() - setup1) as u32;
                    exe.extend_from_slice(CHUNK_MAGIC);
                    exe.extend_from_slice(&z);
                    for p in &mut placed {
                        p.0 = off;
                    }
                    let size = z.len() as u64;
                    for (j, f) in files.iter().enumerate() {
                        let cut = f.cut.min(size / 2);
                        entries.push((placed[j].0, placed[j].1, f, size - cut));
                    }
                } else {
                    let z = compress(&content, f.method);
                    let off = (exe.len() - setup1) as u32;
                    exe.extend_from_slice(CHUNK_MAGIC);
                    exe.extend_from_slice(&z);
                    let cut = f.cut.min(z.len() as u64 / 2);
                    entries.push((off, 0, f, z.len() as u64 - cut));
                }
            }
            if let Some(&last) = entries.last() {
                entries.extend(std::iter::repeat_n(last, repeat));
            }
            // The data entries.
            let count = entries.len() as u32;
            let mut table = Vec::new();
            for (chunk_off, file_off, f, chunk_size) in entries {
                let mut e = vec![0u8; entry_size(v)];
                // The chunk offset is 8 bytes from 6.5.2, 4 before.
                let wide = if v >= (6, 5, 2, 0) { 4 } else { 0 };
                let chunk_off = u64::from(chunk_off) | self.chunk_high << 32;
                e[8..12 + wide].copy_from_slice(&chunk_off.to_le_bytes()[..4 + wide]);
                e[12 + wide..20 + wide].copy_from_slice(&file_off.to_le_bytes());
                e[20 + wide..28 + wide].copy_from_slice(&(f.data.len() as u64).to_le_bytes());
                e[28 + wide..36 + wide].copy_from_slice(&chunk_size.to_le_bytes());
                let mut flags = f.flags;
                if f.method != Method::Stored {
                    flags |= COMPRESSED;
                }
                if f.filtered {
                    flags |= CALL_FILTER;
                }
                if v >= (6, 4, 3, 0) {
                    // Five flags are left: the call filter is bit 2,
                    // encrypted 3, compressed 4.
                    flags = u16::from(flags & CALL_FILTER != 0) << 2
                        | u16::from(flags & ENCRYPTED != 0) << 3
                        | u16::from(flags & COMPRESSED != 0) << 4;
                }
                let at = flags_at(v);
                e[at] = flags as u8;
                if ((5, 1, 13, 0)..(6, 4, 3, 0)).contains(&v) {
                    e[at + 1] = (flags >> 8) as u8;
                }
                table.extend(e);
            }
            // The one method every chunk of the installer is compressed with.
            let method = files
                .iter()
                .map(|f| f.method)
                .find(|m| *m != Method::Stored)
                .unwrap_or(Method::Stored);
            assert!(
                files
                    .iter()
                    .all(|f| f.method == Method::Stored || f.method == method)
            );
            // setup-0: the version, the header and the data entries.
            let setup0 = exe.len();
            let revision = if v.3 == 0 {
                String::new()
            } else {
                format!(".{}", v.3)
            };
            let mut name = format!(
                "Inno Setup Setup Data ({}.{}.{}{revision}){}",
                v.0,
                v.1,
                v.2,
                if self.unicode && v < (6, 3, 0, 0) {
                    " (u)"
                } else {
                    ""
                }
            )
            .into_bytes();
            name.resize(VERSION_STRING, 0);
            exe.extend(name);
            let byte = match method {
                Method::Stored => 0,
                Method::Zlib => 1,
                Method::Bzip2 => 2,
                Method::Lzma1 => 3,
                Method::Lzma2 => 4,
            };
            let header = header_start(
                v,
                self.unicode,
                self.header_method.unwrap_or(byte),
                self.counted.unwrap_or(count),
            );
            if v >= (6, 5, 0, 0) {
                // A checksum, the byte, and the key derivation data.
                exe.extend_from_slice(&[0xc5; 4]);
                exe.push(self.encryption);
                exe.extend_from_slice(&[0x5c; 48]);
            }
            let mut first = block(v, &compress(&header, Method::Lzma1), true);
            let mut second = block(v, &compress(&table, Method::Lzma1), true);
            if self.scrambled {
                // Noise in the first block but for its size, and a size in
                // the second that no limit allows.
                first
                    .iter_mut()
                    .enumerate()
                    .filter(|(i, _)| !(4..8).contains(i))
                    .for_each(|(_, b)| *b ^= 0xa5);
                second[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            exe.extend(first);
            exe.extend(second);
            // The loader table, in the stub's resource.
            let mut loader = LOADER_MAGICS[0].to_vec();
            for word in [1, 0, 0, 0, 0, setup0 as u32, setup1 as u32, 0] {
                loader.extend_from_slice(&u32::to_le_bytes(word));
            }
            if self.table2 {
                // Revision 2: sizes and offsets of 64 bits, a padding word.
                loader.truncate(12);
                loader.extend_from_slice(&2u32.to_le_bytes());
                loader.extend_from_slice(&[0; 8 + 8 + 4 + 4]);
                loader.extend_from_slice(&(setup0 as u64).to_le_bytes());
                loader.extend_from_slice(&(setup1 as u64).to_le_bytes());
                loader.extend_from_slice(&[0; 4 + 4]);
            }
            exe[LOADER_AT..LOADER_AT + loader.len()].copy_from_slice(&loader);
            if self.decoy {
                // Another table where a search for the magic finds it first.
                let mut other = LOADER_MAGICS[0].to_vec();
                for word in [1, 0, 0, 0, 0, 0x10u32, 0x20, 0] {
                    other.extend_from_slice(&word.to_le_bytes());
                }
                exe[0x170..0x170 + 44].copy_from_slice(&other);
            }
            exe
        }
    }

    type Seen = Vec<(String, Vec<u8>, Option<&'static str>, bool)>;

    fn walked(data: &dyn ByteSource, limits: Limits) -> (Seen, Result<(), LimitHit>) {
        let mut budget = Budget::new(limits);
        let mut seen = Vec::new();
        let end = walk(data, &mut budget, &mut |meta, content, _| {
            let mut bytes = Vec::new();
            if let Some(Member::Stream(r)) = content {
                let _ = r.read_to_end(&mut bytes);
            }
            seen.push((meta.name.clone(), bytes, meta.unsupported, meta.encrypted));
            None::<()>
        });
        (seen, end.map(|_| ()))
    }

    fn payload(n: usize, salt: u8) -> Vec<u8> {
        (0..n)
            .map(|i| ((i * 13 + usize::from(salt)) % 251) as u8)
            .collect()
    }

    fn ok(seen: &Seen) -> Vec<Vec<u8>> {
        seen.iter()
            .map(|(n, b, u, _)| {
                assert!(u.is_none(), "{n}: {u:?}");
                b.clone()
            })
            .collect()
    }

    #[test]
    fn every_method_and_version_layout_gives_its_files() {
        let (a, b, c, d) = (
            payload(3000, 1),
            payload(70_000, 2),
            payload(10, 3),
            payload(500, 4),
        );
        for v in [
            (5, 1, 5, 0),
            (5, 1, 13, 0),
            (5, 2, 5, 0),
            (5, 3, 9, 0),
            (5, 3, 10, 0),
            (5, 5, 7, 0),
            (5, 6, 1, 0),
            (6, 0, 0, 0),
            (6, 3, 0, 0),
            (6, 4, 0, 0),
            (6, 4, 0, 1),
            (6, 4, 2, 0),
            (6, 4, 3, 0),
            (6, 5, 0, 0),
            (6, 5, 2, 0),
            (6, 6, 0, 0),
            (6, 6, 1, 0),
            (6, 7, 0, 0),
            (7, 0, 0, 1),
            (7, 0, 0, 3),
        ] {
            // The one compression the setup header names, for every chunk;
            // a file it leaves stored is stored.
            for m in [Method::Zlib, Method::Bzip2, Method::Lzma1, Method::Lzma2] {
                if m == Method::Lzma2 && v < (5, 3, 9, 0) {
                    continue;
                }
                let exe = build(
                    v,
                    &[
                        spec(&a, m),
                        spec(&b, m),
                        spec(&c, Method::Stored),
                        spec(&d, m),
                    ],
                    false,
                );
                let (seen, end) = walked(&exe, Limits::default());
                end.unwrap();
                assert_eq!(
                    ok(&seen),
                    vec![a.clone(), b.clone(), c.clone(), d.clone()],
                    "{v:?} {m:?}"
                );
                assert_eq!(seen[1].0, "inno-file-1");
                assert_eq!(crate::detect(&exe), Some(crate::Format::Inno));
            }
        }
    }

    #[test]
    fn a_non_unicode_build_has_its_lead_bytes_skipped() {
        let a = payload(100, 1);
        for unicode in [false, true] {
            let mut setup = Setup::new((5, 5, 7, 0));
            setup.unicode = unicode;
            let exe = setup.build(&[spec(&a, Method::Zlib)], false);
            let (seen, end) = walked(&exe, Limits::default());
            end.unwrap();
            assert_eq!(ok(&seen), vec![a.clone()], "{unicode}");
        }
    }

    #[test]
    fn the_compression_comes_from_the_header_not_from_the_chunk() {
        // LZMA1 with no position bits: the properties byte is 3, which also
        // opens an LZMA2 stream (dictionary property 3), and the dictionary's
        // low byte 0 is its end marker. Setup decodes by the header.
        let (a, b) = (payload(4000, 1), payload(3000, 2));
        let mut setup = Setup::new((6, 4, 0, 1));
        setup.lzma_pb = 0;
        let exe = setup.build(&[spec(&a, Method::Lzma1), spec(&b, Method::Lzma1)], false);
        let chunk = 0x400 + 4;
        assert_eq!(exe[chunk], 3);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(ok(&seen), vec![a.clone(), b.clone()]);
        // A chunk in another method than the header names is not decoded as
        // what it looks like: an LZMA1 chunk of the usual properties is not
        // LZMA2 (the usual 93 is no dictionary property), and is reported.
        let mut setup = Setup::new((6, 4, 0, 1));
        setup.header_method = Some(4);
        let exe = setup.build(&[spec(&a, Method::Lzma1)], false);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert!(seen.len() == 1 && seen[0].2.is_some() && seen[0].1.is_empty());
    }

    /// Whether the read of each member failed.
    fn failed(data: &dyn ByteSource) -> Vec<bool> {
        let mut out = Vec::new();
        walk(
            data,
            &mut Budget::new(Limits::default()),
            &mut |_, content, _| {
                out.push(match content {
                    Some(Member::Stream(r)) => io::copy(r, &mut io::sink()).is_err(),
                    _ => false,
                });
                None::<()>
            },
        )
        .unwrap();
        out
    }

    #[test]
    fn the_files_of_a_solid_chunk_come_out_in_turn() {
        let (a, b) = (payload(5000, 1), payload(9000, 2));
        let exe = build(
            (6, 4, 0, 1),
            &[
                spec(&a, Method::Lzma2),
                spec(&b, Method::Lzma2),
                spec(&a, Method::Lzma2),
            ],
            true,
        );
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(ok(&seen), vec![a.clone(), b, a]);
        // Through a cache of small blocks, as a file on disk is read.
        let cached =
            crate::source::BlockCache::with_sizes(io::Cursor::new(exe.clone()), 512, 4096).unwrap();
        let (again, _) = walked(&cached, Limits::default());
        assert_eq!(again, seen);
    }

    #[test]
    fn the_x86_filter_is_undone() {
        let mut code = payload(200_000, 9);
        // Calls and jumps forward and back, one across the 64 KiB boundary.
        for (at, rel) in [
            (100usize, 0x1234i32),
            (5000, -0x4321),
            (0xfffd, 0x10),
            (150_000, -8),
        ] {
            code[at] = 0xe8;
            code[at + 1..at + 5].copy_from_slice(&rel.to_le_bytes());
        }
        for v in [
            (5, 2, 0, 0),
            (5, 5, 7, 0),
            (6, 4, 2, 0),
            (6, 4, 3, 0),
            (6, 5, 2, 0),
            (6, 6, 1, 0),
            (6, 7, 0, 0),
            (7, 0, 0, 3),
        ] {
            let exe = build(
                v,
                &[Spec {
                    filtered: true,
                    ..spec(&code, Method::Lzma1)
                }],
                false,
            );
            let (seen, end) = walked(&exe, Limits::default());
            end.unwrap();
            assert!(ok(&seen)[0] == code, "{v:?}");
        }
        // Up to 5.1.x: each call's address made absolute from the offset.
        let mut f = Filter::new((5, 1, 5, 0));
        let mut out = Vec::new();
        f.run(&[0xe8, 0x0a, 0, 0, 0, 0x90], true, &mut out);
        assert_eq!(out, [0xe8, 0x05, 0, 0, 0, 0x90]);
    }

    #[test]
    fn an_encrypted_file_is_password_protected() {
        let a = payload(100, 1);
        for v in [
            (6, 4, 0, 1),
            (6, 4, 3, 0),
            (6, 5, 2, 0),
            (6, 6, 1, 0),
            (6, 7, 0, 0),
            (7, 0, 0, 3),
        ] {
            let exe = build(
                v,
                &[
                    Spec {
                        flags: ENCRYPTED,
                        ..spec(&a, Method::Lzma2)
                    },
                    spec(&a, Method::Lzma2),
                ],
                false,
            );
            let (seen, end) = walked(&exe, Limits::default());
            end.unwrap();
            assert!(seen[0].1.is_empty() && seen[0].2.is_some() && seen[0].3);
            assert_eq!(seen[1].1, a);
        }
    }

    /// An installer before 5.1.5 has no loader resource: the header at 0x30
    /// that points at its table makes it one, which is reported, and a header
    /// whose complement is wrong does not.
    #[test]
    fn an_installer_before_5_1_5_is_told_by_its_header_and_reported() {
        let mut old = vec![0u8; 0x200];
        old[..2].copy_from_slice(b"MZ");
        old[0x30..0x34].copy_from_slice(b"Inno");
        old[0x34..0x38].copy_from_slice(&0x100u32.to_le_bytes());
        old[0x38..0x3c].copy_from_slice(&(!0x100u32).to_le_bytes());
        old[0x100..0x10c].copy_from_slice(b"rDlPtS05\x87eVx");
        assert_eq!(crate::detect(&old), Some(crate::Format::Inno));
        let (seen, end) = walked(&old, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 1);
        let why = seen[0].2.unwrap_or_default();
        assert!(why.contains("of a version before 5.1.5"), "{why}");
        let mut wrong = old.clone();
        wrong[0x38] ^= 1;
        assert_ne!(crate::detect(&wrong), Some(crate::Format::Inno));
        let mut other = old;
        other[0x100..0x10c].copy_from_slice(b"rDlPtS09\x87eVx");
        assert_ne!(crate::detect(&other), Some(crate::Format::Inno));
    }

    #[test]
    fn what_is_not_read_is_reported() {
        let a = payload(100, 1);
        let exe = build((6, 4, 0, 1), &[spec(&a, Method::Zlib)], false);
        let one_report = |exe: &[u8]| {
            let (seen, end) = walked(&exe.to_vec(), Limits::default());
            end.unwrap();
            seen.len() == 1 && seen[0].2.is_some() && seen[0].1.is_empty()
        };
        // Data in setup-1.bin: the table says setup-1 is not in the file.
        let mut ext = exe.clone();
        ext[LOADER_AT + 36..LOADER_AT + 40].fill(0);
        assert!(one_report(&ext));
        // A version before 5.1.5, past 7.0.0.3, one between that has no
        // layout, and no loader table.
        for v in [
            (5, 0, 4, 0),
            (7, 0, 0, 0),
            (7, 0, 0, 2),
            (7, 0, 0, 4),
            (7, 1, 0, 0),
        ] {
            assert!(
                one_report(&build(v, &[spec(&a, Method::Zlib)], false)),
                "{v:?}"
            );
        }
        let mut bare = b"MZ".to_vec();
        bare.extend_from_slice(&[0; 64]);
        bare.extend_from_slice(b"rDlPtS");
        let (seen, _) = walked(&bare, Limits::default());
        assert!(seen.len() == 1 && seen[0].2.unwrap().contains("Inno Setup"));
        // A header that names a compression there is none of, or counts
        // other data entries than the block holds: not laid out as the
        // version says.
        let mut setup = Setup::new((6, 4, 0, 1));
        setup.header_method = Some(9);
        assert!(one_report(&setup.build(&[spec(&a, Method::Zlib)], false)));
        // LZMA2 is known from 5.3.9.
        let mut setup = Setup::new((5, 3, 8, 0));
        setup.header_method = Some(4);
        assert!(one_report(&setup.build(&[spec(&a, Method::Zlib)], false)));
        let mut setup = Setup::new((6, 4, 0, 1));
        setup.counted = Some(2);
        assert!(one_report(&setup.build(&[spec(&a, Method::Zlib)], false)));
        // A chunk without its magic where the entry places it.
        let mut odd = exe.clone();
        odd[0x400] = 0;
        assert!(one_report(&odd));
    }

    #[test]
    fn the_loader_table_is_the_one_in_the_resource() {
        let a = payload(100, 1);
        let mut setup = Setup::new((6, 4, 0, 1));
        setup.decoy = true;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        // A table with the magic comes first in the file, pointing nowhere.
        assert!(exe[0x170..].starts_with(LOADER_MAGICS[0]));
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(ok(&seen), vec![a.clone()]);
        // The magic outside a resource of the executable is no table.
        let mut bare = exe.clone();
        bare[0x3c] = 0;
        let (seen, _) = walked(&bare, Limits::default());
        assert!(seen.len() == 1 && seen[0].2.is_some());
        // A resource in two languages is the same table in both, or none.
        let mut two = exe.clone();
        two[0x230 + 14] = 2;
        let (seen, _) = walked(&two, Limits::default());
        assert_eq!(ok(&seen), vec![a.clone()]);
        let other = LOADER_AT + 0x30;
        let copy = two[LOADER_AT..LOADER_AT + 44].to_vec();
        two[other..other + 44].copy_from_slice(&copy);
        two[other + 32..other + 36].copy_from_slice(&0x10u32.to_le_bytes());
        two[0x260..0x264].copy_from_slice(&(0x1000u32 + (other - 0x200) as u32).to_le_bytes());
        let (seen, _) = walked(&two, Limits::default());
        assert!(seen.len() == 1 && seen[0].2.is_some());
    }

    #[test]
    fn a_data_entry_is_two_bytes_smaller_from_6_4_3_and_four_larger_from_6_5_2() {
        // Sizes of the entries of the released installers.
        assert_eq!(entry_size((6, 4, 0, 1)), 87);
        assert_eq!(entry_size((6, 4, 2, 0)), 87);
        assert_eq!(entry_size((6, 4, 3, 0)), 85);
        assert_eq!(entry_size((6, 5, 0, 0)), 85);
        assert_eq!(entry_size((6, 5, 2, 0)), 89);
    }

    #[test]
    fn a_chunk_offset_has_64_bits_from_6_5_2() {
        let a = payload(100, 1);
        let mut setup = Setup::new((6, 5, 2, 0));
        setup.chunk_high = 1;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        // The chunk is 4 GiB further than the lower half says: not there.
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert!(seen.len() == 1 && seen[0].2.is_some());
        // Before 6.5.2 the entry has no room for the upper half.
        let mut setup = Setup::new((6, 5, 0, 0));
        setup.chunk_high = 1;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(ok(&seen), vec![a]);
    }

    #[test]
    fn the_encryption_header_of_6_5_is_skipped_and_only_encrypted_when_it_says_so() {
        let a = payload(100, 1);
        // Files encrypted but the setup headers readable: the files are
        // listed, none of them reported as encrypted.
        let mut setup = Setup::new((6, 5, 0, 0));
        setup.encryption = 1;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(ok(&seen), vec![a.clone()]);
        assert!(!seen[0].3);
        // The setup headers encrypted too: one report, password protected.
        setup.scrambled = true;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert!(seen.len() == 1 && seen[0].2.is_some() && seen[0].3);
        // The same bytes with the installer not saying it is encrypted are a
        // header that is not understood, not an encrypted installer: here
        // the size in the second block is over the limit.
        setup.encryption = 0;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        let (seen, end) = walked(&exe, Limits::default());
        assert!(seen.is_empty() && end.is_err());
    }

    #[test]
    fn a_loader_table_of_revision_2_has_64_bit_offsets() {
        let a = payload(100, 1);
        let mut setup = Setup::new((6, 4, 3, 0));
        setup.table2 = true;
        let exe = setup.build(&[spec(&a, Method::Zlib)], false);
        assert_eq!(le32(&exe, LOADER_AT + 12), Some(2));
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(ok(&seen), vec![a.clone()]);
        // The upper half of an offset counts: setup-0 is not at its lower
        // half, and the installer is reported, not read from there.
        for at in [LOADER_AT + 40, LOADER_AT + 48] {
            let mut far = exe.clone();
            far[at + 4] = 1;
            let (seen, _) = walked(&far, Limits::default());
            assert!(seen.len() == 1 && seen[0].2.is_some(), "{at:#x}");
        }
    }

    #[test]
    fn the_stored_size_of_a_block_has_64_bits_from_6_7_0() {
        let v = (6, 7, 0, 0);
        let a = payload(100, 1);
        let exe = build(v, &[spec(&a, Method::Zlib)], false);
        assert_eq!(block_header(v), 13);
        let first = le32(&exe, LOADER_AT + 32).unwrap() as usize + VERSION_STRING + 53;
        let second = first + 13 + le64(&exe, first + 4).unwrap() as usize;
        // The upper half of the first block's size sends the second block out
        // of the file: the installer is reported, not read from the lower half.
        let mut far = exe.clone();
        far[first + 8] = 1;
        let (seen, end) = walked(&far, Limits::default());
        end.unwrap();
        assert!(seen.len() == 1 && seen[0].2.is_some(), "{seen:?}");
        // That of the second block is over the buffer limit.
        let mut big = exe;
        big[second + 8] = 1;
        let (seen, end) = walked(&big, Limits::default());
        assert!(seen.is_empty() && !end.unwrap_err().is_corrupt());
    }

    #[test]
    fn an_installer_cut_short_gives_what_it_holds() {
        let a = payload(50_000, 1);
        let exe = build(
            (6, 4, 0, 1),
            &[spec(&a, Method::Stored), spec(&a, Method::Zlib)],
            false,
        );
        // The file table is at the end, so a cut loses part of it: reported.
        let (seen, end) = walked(&exe[..exe.len() - 10].to_vec(), Limits::default());
        end.unwrap();
        assert!(seen.len() == 1 && seen[0].2.is_some());
        // A chunk that ends before the file it holds does: the file comes out
        // as far as the chunk goes and the read then fails, stored,
        // compressed and with the x86 filter undone.
        let cut = |m, filtered| Spec {
            cut: 1000,
            filtered,
            ..spec(&a, m)
        };
        for (m, filtered) in [
            (Method::Stored, false),
            (Method::Lzma2, false),
            (Method::Zlib, true),
        ] {
            let exe = build((6, 4, 0, 1), &[cut(m, filtered)], false);
            let (seen, end) = walked(&exe, Limits::default());
            end.unwrap();
            assert!(seen.len() == 1 && seen[0].2.is_none());
            assert!(seen[0].1.len() < a.len() && !seen[0].1.is_empty(), "{m:?}");
            assert_eq!(failed(&exe), [true], "{m:?}");
        }
        // The same file whole is read without a failure.
        let exe = build((6, 4, 0, 1), &[spec(&a, Method::Stored)], false);
        assert_eq!(failed(&exe), [false]);
        // A file the chunk ends before is an error, not a whole file.
        let mut out = Vec::new();
        let short = Exact {
            inner: &b"abc"[..],
            left: 5,
        }
        .read_to_end(&mut out);
        assert!(short.is_err() && out == b"abc");
        let mut whole = Exact {
            inner: &b"abcdef"[..],
            left: 5,
        };
        out.clear();
        whole.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abcde");
    }

    #[test]
    fn many_entries_are_held_to_the_member_count() {
        let a = payload(10, 1);
        let files: Vec<Spec> = (0..50).map(|_| spec(&a, Method::Stored)).collect();
        let exe = build((5, 5, 7, 0), &files, false);
        let limits = Limits {
            max_members: 10,
            ..Limits::default()
        };
        let (seen, end) = walked(&exe, limits);
        assert_eq!(seen.len(), 10);
        assert!(!end.unwrap_err().is_corrupt());
    }

    #[test]
    fn entries_that_go_back_over_a_chunk_are_held_to_the_scan_budget() {
        let (a, b) = (payload(50_000, 1), payload(1000, 2));
        let files = [spec(&a, Method::Lzma2), spec(&b, Method::Lzma2)];
        // The last file again and again: each time the chunk is decoded from
        // its start up to it.
        let exe = build_repeating((6, 4, 0, 1), &files, true, 100);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert_eq!(seen.len(), 102);
        let limits = Limits {
            max_scanned_bytes: 1_000_000,
            ..Limits::default()
        };
        let (seen, end) = walked(&exe, limits);
        assert!(seen.len() < 30, "{}", seen.len());
        assert!(!end.unwrap_err().is_corrupt());
    }

    #[test]
    fn a_file_table_damaged_part_way_is_reported() {
        let a = payload(10, 1);
        let files: Vec<Spec> = (0..200).map(|_| spec(&a, Method::Stored)).collect();
        let mut exe = build((6, 4, 0, 1), &files, false);
        let first = le32(&exe, LOADER_AT + 32).unwrap() as usize + VERSION_STRING;
        let header = block_header((6, 4, 0, 1));
        let second = first + header + le32(&exe, first + 4).unwrap() as usize;
        // Past the block header, the first piece's CRC and the LZMA header.
        let at = second + header + 4 + 5 + 40;
        exe[at..at + 60].fill(0xff);
        let (seen, end) = walked(&exe, Limits::default());
        end.unwrap();
        assert!(
            seen.iter()
                .any(|(n, _, u, _)| n == "inno-setup-payload" && u.is_some()),
            "{seen:?}"
        );
    }

    #[test]
    fn a_header_block_over_the_buffer_limit_is_a_limit() {
        let a = payload(10, 1);
        let files: Vec<Spec> = (0..50).map(|_| spec(&a, Method::Stored)).collect();
        let exe = build((5, 5, 7, 0), &files, false);
        let limits = Limits {
            max_buffer_bytes: 100,
            ..Limits::default()
        };
        let (seen, end) = walked(&exe, limits);
        assert!(seen.is_empty());
        assert!(!end.unwrap_err().is_corrupt());
    }

    #[test]
    fn the_version_string_is_read() {
        assert_eq!(
            parse_version(b"Inno Setup Setup Data (5.5.7) (u)\0\0"),
            Some(((5, 5, 7, 0), true))
        );
        assert_eq!(
            parse_version(b"Inno Setup Setup Data (5.5.7)\0\0"),
            Some(((5, 5, 7, 0), false))
        );
        // The release of 6.4.0 has a revision; 6.3.0 on is Unicode whatever
        // the string says.
        assert_eq!(
            parse_version(b"Inno Setup Setup Data (6.4.0.1)"),
            Some(((6, 4, 0, 1), true))
        );
        assert_eq!(parse_version(b"Inno Setup Setup Data (6.4.0.1.2)"), None);
        assert_eq!(parse_version(b"Inno Setup Setup Data (6.x.0)"), None);
        assert_eq!(
            parse_version(b"My Inno Setup Extensions Setup Data (3.0.6.1)"),
            None
        );
    }

    /// Walks the released installers of `tests/inno/installers.txt`, which
    /// `make test-inno` fetches into the directory `EXAV_DEBUG_INNO_DIR`:
    /// every data entry must come out whole, with the SHA-256 the installer
    /// stores for it.
    #[test]
    #[ignore = "needs the installers: make test-inno"]
    fn released_installers_give_every_file_whole_with_its_checksum() {
        use sha2::{Digest, Sha256};
        let dir = std::env::var("EXAV_DEBUG_INNO_DIR")
            .expect("EXAV_DEBUG_INNO_DIR is not set: run make test-inno");
        let list = include_str!("../../tests/inno/installers.txt");
        let rows: Vec<Vec<&str>> = list
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert!(!rows.is_empty());
        for row in rows {
            let [version, url, _] = row[..] else {
                panic!("installers.txt: {row:?}");
            };
            let path = std::path::Path::new(&dir).join(url.rsplit('/').next().unwrap());
            let exe = std::fs::read(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            // The entries as the installer stores them.
            let (setup0, _) = loader(&exe).expect("loader table");
            let (v, _) = parse_version(&exe.window(setup0, VERSION_STRING)).expect("version");
            assert!(is_read(v), "{version}: data version {v:?}");
            assert_eq!(checksum_size(v), 32, "{version}: SHA-256 expected");
            let first = setup0 + VERSION_STRING + encryption_header(v);
            let (stored, _) = block_head(&exe, first, v).expect("block header");
            let max = Limits::default().max_buffer_bytes;
            let second = first + block_header(v) + stored as usize;
            let (data, damaged) = super::block(&exe, second, v, max)
                .unwrap()
                .expect("data entries");
            assert!(!damaged && data.len() % entry_size(v) == 0, "{version}");
            let (seen, end) = walked(&exe, Limits::default());
            end.unwrap();
            let count = data.len() / entry_size(v);
            assert_eq!(seen.len(), count, "{version}");
            for (i, e) in data.chunks_exact(entry_size(v)).enumerate() {
                let want = format!("inno-file-{i}");
                let (_, bytes, unsupported, _) = seen
                    .iter()
                    .find(|m| m.0 == want)
                    .unwrap_or_else(|| panic!("{version}: no {want}"));
                assert!(unsupported.is_none(), "{version} {want}: {unsupported:?}");
                assert_eq!(
                    bytes.len() as u64,
                    le64(e, entry_base(v) - 16).unwrap(),
                    "{version} {want}: short or long"
                );
                assert_eq!(
                    Sha256::digest(bytes)[..],
                    e[entry_base(v)..entry_base(v) + 32],
                    "{version} {want}: checksum"
                );
            }
            println!("{version}: {count} files, all whole, checksums verified");
        }
    }
}
