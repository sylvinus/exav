//! WIM — the Windows Imaging Format.
//!
//! Windows mounts a `.wim` natively (`DISM`, and Explorer via `wimmount`), 7-Zip
//! opens one, and it is the payload format of every Windows installer image. As
//! a delivery container it is ordinary, and its file data is chunk-compressed,
//! so a payload inside shows none of its bytes to a raw scan.
//!
//! Implemented from Microsoft's published WIM file format specification. All
//! fields are **little-endian**.
//!
//! ```text
//! header (208 bytes)  -> offset table resource
//!   offset table      -> one 50-byte entry per resource: where it is, how big,
//!                        and the SHA-1 of its uncompressed bytes
//!   metadata resource -> the directory tree, mapping each name to a SHA-1
//!   file resources    -> chunk-compressed data
//! ```
//!
//! The image records the SHA-1 of every resource. A resource that decodes in
//! full and fails it is scanned all the same, as a ZIP member failing its
//! CRC-32 is: the bytes are there, and an attacker sets the hash as easily as
//! the data. With checksums verified (`Budget::set_verify_checksums`) it is
//! reported instead.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::io::{self, Read};

use sha1::{Digest, Sha1};

use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_entry, emit_stream};
use crate::{Budget, Entry, LimitHit};

/// One offset-table entry: a 24-byte resource header, then part number,
/// reference count and the 20-byte SHA-1.
const TABLE_ENTRY_LEN: usize = 50;
const HASH_LEN: usize = 20;

/// Resource flags.
const RESOURCE_METADATA: u8 = 0x02;
const RESOURCE_COMPRESSED: u8 = 0x04;
/// The resource is split across the parts of a spanned image, so this file holds
/// only some of its bytes.
const RESOURCE_SPANNED: u8 = 0x08;

/// Header flags naming the chunk codec.
const FLAG_COMPRESS_XPRESS: u32 = 0x0002_0000;
const FLAG_COMPRESS_LZX: u32 = 0x0004_0000;
const FLAG_COMPRESS_LZMS: u32 = 0x0008_0000;

/// The default chunk size when the header does not give one.
const DEFAULT_CHUNK: u32 = 32768;

/// Within a directory entry: the length of the file name, then the name itself
/// (UTF-16LE, NUL-terminated). The fixed area before it is the timestamps, the
/// resource hash and the reparse/hard-link union.
const DENTRY_NAME_LEN_OFF: usize = 100;
const DENTRY_NAME_OFF: usize = 102;

/// Walk guards, both reported when hit.
const MAX_RESOURCES: usize = 65536;
const MAX_DENTRIES: usize = 200_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Codec {
    None,
    Xpress,
    Lzx,
    Lzms,
}

fn le_u16(d: &[u8], off: usize) -> u16 {
    crate::bytes::at(d, off, 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    crate::bytes::at(d, off, 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn le_u64(d: &[u8], off: usize) -> u64 {
    crate::bytes::at(d, off, 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .unwrap_or(0)
}

/// Where a resource lives and what it should decompress to.
#[derive(Clone)]
struct Resource {
    size_in_wim: u64,
    flags: u8,
    offset: u64,
    original_size: u64,
    hash: [u8; HASH_LEN],
}

/// Parse a 24-byte resource header: a 7-byte size, a flags byte, then the offset
/// and the uncompressed size.
fn resource_header(data: &[u8], off: usize) -> Resource {
    let mut size = 0u64;
    for i in 0..7usize {
        let b = data.get(off.saturating_add(i)).copied().unwrap_or(0);
        size |= u64::from(b) << i.saturating_mul(8);
    }
    Resource {
        size_in_wim: size,
        flags: data.get(off.saturating_add(7)).copied().unwrap_or(0),
        offset: le_u64(data, off.saturating_add(8)),
        original_size: le_u64(data, off.saturating_add(16)),
        hash: [0; HASH_LEN],
    }
}

/// The most a chunk may decode to. The codecs' windows go to 2 MiB; a header
/// that names more is not a chunk size any image has.
const MAX_CHUNK: u32 = 1 << 24;

/// A resource's bytes, decoded a chunk at a time as they are read.
struct ResourceReader<'a> {
    src: &'a dyn ByteSource,
    codec: Codec,
    /// Where the chunks' bytes start in the image, and how many there are.
    body: usize,
    body_len: usize,
    /// The start of chunks 1 to n-1 in the body, as the image gives them.
    table: Vec<u8>,
    wide: bool,
    chunk: usize,
    n_chunks: usize,
    original: u64,
    /// The next chunk to decode, and how many bytes have been decoded.
    next: usize,
    given: u64,
    /// The chunk being served, and how much of it has been.
    buf: Vec<u8>,
    at: usize,
}

fn bad(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

impl ResourceReader<'_> {
    /// Where chunk `i` starts in the body.
    fn start(&self, i: usize) -> usize {
        let entry = if self.wide { 8 } else { 4 };
        let at = i.saturating_sub(1).saturating_mul(entry);
        if i == 0 {
            0
        } else if self.wide {
            crate::bytes::to_usize(le_u64(&self.table, at))
        } else {
            le_u32(&self.table, at) as usize
        }
    }

    /// Decode the chunk that is next into `buf`.
    fn decode(&mut self) -> io::Result<()> {
        let i = self.next;
        let s = self.start(i);
        let e = if i.saturating_add(1) < self.n_chunks {
            self.start(i.saturating_add(1))
        } else {
            self.body_len
        };
        if s > e || e > self.body_len {
            return Err(bad("WIM chunk lies outside its resource"));
        }
        let want = crate::bytes::to_usize(
            (self.chunk as u64).min(self.original.saturating_sub(self.given)),
        );
        // A chunk that did not compress is stored verbatim, and is then exactly
        // as long as what it decodes to; only that much of it is read.
        let stored = e.saturating_sub(s) >= want;
        let len = if stored { want } else { e.saturating_sub(s) };
        let cdata = self.src.window(self.body.saturating_add(s), len);
        if cdata.len() != len {
            return Err(bad("WIM chunk could not be read"));
        }
        self.buf = if stored {
            cdata.into_owned()
        } else {
            match self.codec {
                Codec::Xpress => xpress::decompress(&cdata, want).ok_or(bad("WIM XPRESS chunk"))?,
                Codec::Lzx => lzx::decompress(&cdata, want).ok_or(bad("WIM LZX chunk"))?,
                // An uncompressed image should have had the flag clear; if a
                // resource claims compression anyway there is nothing to
                // decode it with.
                Codec::None | Codec::Lzms => return Err(bad("WIM resource names no chunk codec")),
            }
        };
        self.at = 0;
        self.next = i.saturating_add(1);
        self.given = self.given.saturating_add(self.buf.len() as u64);
        Ok(())
    }
}

impl Read for ResourceReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(rest) = self.buf.get(self.at..).filter(|r| !r.is_empty()) {
                let n = rest.len().min(out.len());
                out[..n].copy_from_slice(&rest[..n]);
                self.at = self.at.saturating_add(n);
                return Ok(n);
            }
            if self.next >= self.n_chunks || self.given >= self.original {
                return Ok(0);
            }
            self.decode()?;
        }
    }
}

/// A reader of resource `res`'s bytes. `Err` names a reason worth reporting;
/// the bytes are not checked against the recorded hash here.
fn open_resource<'a>(
    src: &'a dyn ByteSource,
    res: &Resource,
    codec: Codec,
    chunk_size: u32,
    max_buffer: u64,
) -> Result<Box<dyn Read + 'a>, &'static str> {
    let outside = "WIM resource lies outside the image";
    let start = usize::try_from(res.offset).map_err(|_| outside)?;
    let len = usize::try_from(res.size_in_wim).map_err(|_| outside)?;
    let end = start.checked_add(len).filter(|&e| e <= src.len());
    let Some(end) = end else {
        return Err(outside);
    };

    if res.flags & RESOURCE_COMPRESSED == 0 {
        return Ok(Box::new(Reader::range(src, start, end)));
    }
    if codec == Codec::Lzms {
        return Err("WIM LZMS-compressed resource");
    }
    let chunk = chunk_size.max(1);
    if chunk > MAX_CHUNK {
        return Err("WIM chunk size is larger than any codec's window");
    }
    let chunk = chunk as usize;
    let original = res.original_size;
    let n_chunks = crate::bytes::to_usize(original.div_ceil(chunk as u64)).max(1);

    // The chunk table gives the start of chunks 1..n-1 relative to the end of
    // the table; chunk 0 always starts there. Entries are u32 unless the
    // uncompressed resource is over 4 GiB.
    let wide = original > u64::from(u32::MAX);
    let entry = if wide { 8 } else { 4 };
    let table_len = n_chunks.saturating_sub(1).saturating_mul(entry);
    if table_len > len {
        return Err("WIM chunk table is truncated");
    }
    if table_len as u64 > max_buffer {
        return Err("WIM chunk table exceeds max-buffer");
    }
    let table = src.window(start, table_len);
    if table.len() != table_len {
        return Err("WIM chunk table is truncated");
    }
    Ok(Box::new(ResourceReader {
        src,
        codec,
        body: start.saturating_add(table_len),
        body_len: len.saturating_sub(table_len),
        table: table.into_owned(),
        wide,
        chunk,
        n_chunks,
        original,
        next: 0,
        given: 0,
        buf: Vec::new(),
        at: 0,
    }))
}

/// Resource `res` read whole, up to `max_buffer` bytes.
fn read_resource(
    src: &dyn ByteSource,
    res: &Resource,
    codec: Codec,
    chunk_size: u32,
    max_buffer: u64,
) -> Result<Vec<u8>, &'static str> {
    let compressed = res.flags & RESOURCE_COMPRESSED != 0;
    let size = if compressed {
        res.original_size
    } else {
        res.size_in_wim
    };
    if size > max_buffer {
        return Err("WIM resource exceeds max-buffer");
    }
    let mut reader = open_resource(src, res, codec, chunk_size, max_buffer)?;
    let mut out = Vec::new();
    reader
        .by_ref()
        .take(size.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| "WIM resource did not decode")?;
    Ok(out)
}

/// A resource's bytes, hashed as they are read: at the end they are the
/// resource the image recorded, or they are not.
struct Checked<'a> {
    inner: Box<dyn Read + 'a>,
    hasher: Sha1,
    expected: [u8; HASH_LEN],
}

impl Read for Checked<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(out)?;
        if n > 0 {
            self.hasher.update(&out[..n]);
        } else if !out.is_empty() && self.hasher.clone().finalize().as_slice() != self.expected {
            return Err(crate::checksum_mismatch("WIM SHA-1"));
        }
        Ok(n)
    }
}

mod lzx;

/// A member that is only a report.
fn report<T>(
    name: String,
    size: u64,
    reason: &'static str,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    emit_entry(Entry::unsupported(name, size, false, reason), budget, visit)
}

/// How much of the image is read to tell it is one and to read its header.
const HEADER_READ: usize = 256;

/// Walk a WIM image. Its header, its table of resources and its directory
/// tree are read from where they are in the source; each file resource is then
/// decoded a chunk at a time as it is read, so neither the image nor a
/// resource is held.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let head = src.window(0, HEADER_READ);
    let data: &[u8] = &head;
    if !crate::formats::sniff::is(data, crate::Format::Wim) {
        return Ok(None);
    }
    let max_buffer = budget.limits.max_buffer_bytes;
    let flags = le_u32(data, 16);
    let codec = if flags & FLAG_COMPRESS_LZMS != 0 {
        Codec::Lzms
    } else if flags & FLAG_COMPRESS_LZX != 0 {
        Codec::Lzx
    } else if flags & FLAG_COMPRESS_XPRESS != 0 {
        Codec::Xpress
    } else {
        Codec::None
    };
    let chunk_size = match le_u32(data, 20) {
        0 => DEFAULT_CHUNK,
        n => n,
    };

    // The offset table is itself a resource.
    let table_res = resource_header(data, 48);
    let table_at = usize::try_from(table_res.offset).ok();
    let table_len = usize::try_from(table_res.size_in_wim).ok();
    let inside = table_at
        .zip(table_len)
        .filter(|(at, len)| at.checked_add(*len).is_some_and(|end| end <= src.len()));
    let Some((table_at, table_len)) = inside else {
        budget.count_entry()?;
        return report(
            "<wim-offset-table>".to_string(),
            0,
            "WIM offset table lies outside the image",
            budget,
            visit,
        );
    };
    let listed = table_len.checked_div(TABLE_ENTRY_LEN).unwrap_or(0);
    let table = src.window(
        table_at,
        listed.min(MAX_RESOURCES).saturating_mul(TABLE_ENTRY_LEN),
    );

    let mut resources: Vec<Resource> = Vec::new();
    for i in 0..listed.min(MAX_RESOURCES) {
        let o = i.saturating_mul(TABLE_ENTRY_LEN);
        let mut r = resource_header(&table, o);
        if let Some(h) = crate::bytes::at(&table, o.saturating_add(30), HASH_LEN) {
            r.hash.copy_from_slice(h);
        }
        resources.push(r);
    }
    if listed > MAX_RESOURCES {
        budget.count_entry()?;
        if let Some(r) = report(
            format!("<wim-resources-beyond-{MAX_RESOURCES}>"),
            0,
            "too many WIM resources to enumerate them all",
            budget,
            &mut *visit,
        )? {
            return Ok(Some(r));
        }
    }

    // The metadata resource holds the directory tree, which is what gives the
    // file resources their names. Failing to read it costs names, not content,
    // so the resources are still emitted below.
    let mut names: HashMap<[u8; HASH_LEN], String> = HashMap::new();
    for res in resources
        .iter()
        .filter(|r| r.flags & RESOURCE_METADATA != 0)
    {
        if let Ok(meta) = read_resource(src, res, codec, chunk_size, max_buffer) {
            collect_names(&meta, &mut names);
        }
    }

    for (i, res) in resources.iter().enumerate() {
        if res.flags & RESOURCE_METADATA != 0 || res.original_size == 0 {
            continue;
        }
        let name = names
            .get(&res.hash)
            .cloned()
            .unwrap_or_else(|| format!("wim-resource-{i}"));

        if res.flags & RESOURCE_SPANNED != 0 {
            // The rest of this resource is in another part of the image set,
            // which exav is not scanning.
            budget.count_entry()?;
            if let Some(r) = report(
                name,
                res.size_in_wim,
                "WIM resource continues in another part of a spanned image",
                budget,
                &mut *visit,
            )? {
                return Ok(Some(r));
            }
            continue;
        }

        budget.count_entry()?;
        let opened = open_resource(src, res, codec, chunk_size, max_buffer);
        let reader = match opened {
            Ok(r) => r,
            Err(reason) => {
                if let Some(r) = report(name, res.size_in_wim, reason, budget, &mut *visit)? {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        // A SHA-1 mismatch once the resource has decoded hides nothing: the
        // bytes are scanned, as a ZIP member's are, and it is an error at the
        // end of the member only when checksums are verified.
        let mut reader: Box<dyn Read + '_> = if budget.should_verify_checksums() {
            Box::new(Checked {
                inner: reader,
                hasher: Sha1::new(),
                expected: res.hash,
            })
        } else {
            reader
        };
        let meta = MemberMeta {
            name,
            comp_size: res.size_in_wim,
            size: Some(if res.flags & RESOURCE_COMPRESSED == 0 {
                res.size_in_wim
            } else {
                res.original_size
            }),
            ..MemberMeta::default()
        };
        if let Some(r) = emit_stream(&meta, &mut *reader, budget, &mut *visit)? {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Walk the metadata resource's directory tree, mapping each file's SHA-1 to its
/// path. Anything unparseable costs a name, never content, so this is
/// deliberately forgiving.
fn collect_names(meta: &[u8], out: &mut HashMap<[u8; HASH_LEN], String>) {
    // The security table comes first: its own length, rounded up to 8.
    let sec_len = le_u32(meta, 0) as usize;
    let Some(root) = sec_len.checked_next_multiple_of(8) else {
        return;
    };
    let mut stack = vec![(root, String::new())];
    let mut walked = 0usize;

    while let Some((mut off, prefix)) = stack.pop() {
        loop {
            walked = walked.saturating_add(1);
            if walked > MAX_DENTRIES {
                return;
            }
            let len = crate::bytes::to_usize(le_u64(meta, off));
            if len < DENTRY_NAME_OFF || len > meta.len().saturating_sub(off) {
                break; // an end-of-directory marker is a zero length
            }
            let attributes = le_u32(meta, off.saturating_add(8));
            let subdir = crate::bytes::to_usize(le_u64(meta, off.saturating_add(16)));
            let name_len = le_u16(meta, off.saturating_add(DENTRY_NAME_LEN_OFF)) as usize;
            let name_at = off.saturating_add(DENTRY_NAME_OFF);
            let name = meta
                .get(name_at..)
                .and_then(|rest| rest.get(..name_len))
                .map(|raw| {
                    let units: Vec<u16> = raw
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .copied()
                        .map(u16::from_le_bytes)
                        .collect();
                    String::from_utf16_lossy(&units)
                })
                .unwrap_or_default();
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            // FILE_ATTRIBUTE_DIRECTORY. Testing the attribute rather than
            // `subdir != 0` keeps an empty directory from being recorded as a
            // file with an all-zero hash, which would shadow a real resource.
            let is_dir = attributes & 0x10 != 0;
            if is_dir {
                if subdir != 0 && subdir < meta.len() {
                    stack.push((subdir, path.clone()));
                }
            } else if let Some(h) = crate::bytes::at(meta, off.saturating_add(64), HASH_LEN) {
                let mut hash = [0u8; HASH_LEN];
                hash.copy_from_slice(h);
                out.entry(hash).or_insert(path);
            }
            // Dentries are padded to an 8-byte boundary.
            let Some(padded) = len.checked_next_multiple_of(8) else {
                break;
            };
            off = off.saturating_add(padded);
        }
    }
}

/// XPRESS Huffman (`MS-XCA` §2.2), the lighter of the two classic WIM codecs.
///
/// Each chunk starts with a 256-byte table of 4-bit code lengths for 512
/// symbols, low nibble first. The bitstream that follows is read as 16-bit
/// little-endian words into a left-aligned 32-bit window, most significant bit
/// first — and long match lengths escape into *bytes* taken from the same
/// position, so the bit reader and the byte reader share one cursor.
// A codec, as `lzx` is: its sums are on bit counts, code lengths of 15 or
// less and a 16-bit offset slot, and on positions inside the chunk it was
// handed.
#[allow(clippy::arithmetic_side_effects)]
mod xpress {
    const TABLE_BYTES: usize = 256;
    const SYMBOLS: usize = 512;
    const MAX_LEN: u32 = 15;

    /// Canonical Huffman, decoded by walking code lengths. Slower than a lookup
    /// table, with no table-construction edge cases to get wrong.
    struct Huffman {
        /// First code of each length, and where its symbols start in `sorted`.
        first_code: [u32; MAX_LEN as usize + 2],
        first_index: [u32; MAX_LEN as usize + 2],
        count: [u32; MAX_LEN as usize + 2],
        /// Symbols ordered by (length, symbol).
        sorted: Vec<u16>,
    }

    impl Huffman {
        fn new(lengths: &[u8]) -> Option<Huffman> {
            let mut count = [0u32; MAX_LEN as usize + 2];
            for &l in lengths {
                if l as u32 > MAX_LEN {
                    return None;
                }
                count[l as usize] += 1;
            }
            count[0] = 0;
            let mut first_code = [0u32; MAX_LEN as usize + 2];
            let mut first_index = [0u32; MAX_LEN as usize + 2];
            let mut code = 0u32;
            let mut index = 0u32;
            for len in 1..=MAX_LEN as usize {
                code = (code + count[len - 1]) << 1;
                first_code[len] = code;
                first_index[len] = index;
                index += count[len];
            }
            let mut sorted = vec![0u16; index as usize];
            let mut next = first_index;
            for (sym, &l) in lengths.iter().enumerate() {
                if l == 0 {
                    continue;
                }
                sorted[next[l as usize] as usize] = sym as u16;
                next[l as usize] += 1;
            }
            Some(Huffman {
                first_code,
                first_index,
                count,
                sorted,
            })
        }
    }

    /// A left-aligned 32-bit bit window over 16-bit little-endian words.
    struct Bits<'a> {
        data: &'a [u8],
        pos: usize,
        buf: u32,
        /// Valid bits currently in `buf`, counted from the top.
        n: u32,
    }

    impl<'a> Bits<'a> {
        fn new(data: &'a [u8]) -> Bits<'a> {
            let mut b = Bits {
                data,
                pos: 0,
                buf: 0,
                n: 0,
            };
            let hi = b.word() as u32;
            let lo = b.word() as u32;
            b.buf = (hi << 16) | lo;
            b.n = 32;
            b
        }

        fn word(&mut self) -> u16 {
            let w = self
                .data
                .get(self.pos..self.pos + 2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .unwrap_or(0);
            self.pos += 2;
            w
        }

        /// Bit `i` from the top of the window, counting from 1.
        fn bit(&self, i: u32) -> u32 {
            (self.buf >> (32 - i)) & 1
        }

        fn take(&mut self, k: u32) {
            if k == 0 {
                return;
            }
            self.buf <<= k;
            self.n -= k;
            // Strictly below 16, not at or below: refilling one word early
            // shifts the shared byte cursor, and the long-length escapes read
            // from that cursor. Decoding then stays correct right up to the
            // first long match and goes wrong there.
            if self.n < 16 {
                let w = self.word() as u32;
                self.buf |= w << (16 - self.n);
                self.n += 16;
            }
        }

        fn read(&mut self, k: u32) -> u32 {
            if k == 0 {
                return 0;
            }
            let v = self.buf >> (32 - k);
            self.take(k);
            v
        }

        /// A raw byte, taken from the shared cursor: long match lengths are
        /// stored as bytes interleaved with the 16-bit words.
        fn byte(&mut self) -> u8 {
            let b = self.data.get(self.pos).copied().unwrap_or(0);
            self.pos += 1;
            b
        }

        fn u16(&mut self) -> u16 {
            let lo = self.byte() as u16;
            let hi = self.byte() as u16;
            lo | (hi << 8)
        }

        fn symbol(&mut self, h: &Huffman) -> Option<u16> {
            let mut code = 0u32;
            for len in 1..=MAX_LEN {
                code = (code << 1) | self.bit(len);
                let count = h.count[len as usize];
                if count > 0 && code >= h.first_code[len as usize] {
                    let idx = code - h.first_code[len as usize];
                    if idx < count {
                        let sym = *h.sorted.get((h.first_index[len as usize] + idx) as usize)?;
                        self.take(len);
                        return Some(sym);
                    }
                }
            }
            None
        }
    }

    pub(super) fn decompress(data: &[u8], out_len: usize) -> Option<Vec<u8>> {
        let table = data.get(..TABLE_BYTES)?;
        let mut lengths = [0u8; SYMBOLS];
        for (i, &b) in table.iter().enumerate() {
            lengths[i * 2] = b & 0x0F;
            lengths[i * 2 + 1] = b >> 4;
        }
        let huff = Huffman::new(&lengths)?;
        let mut bits = Bits::new(&data[TABLE_BYTES..]);
        let mut out: Vec<u8> = Vec::with_capacity(out_len);

        while out.len() < out_len {
            let sym = bits.symbol(&huff)?;
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let sym = (sym - 256) as u32;
            let length_header = sym & 0x0F;
            let offset_slot = sym >> 4;

            let mut length = length_header as usize;
            if length_header == 15 {
                // Long lengths escape into the byte stream, twice over.
                let b = bits.byte() as usize;
                length = if b == 255 {
                    let m = bits.u16() as usize;
                    if m < 15 {
                        return None;
                    }
                    m - 15
                } else {
                    b
                };
                length += 15;
            }
            length += 3;

            let offset = (1usize << offset_slot) + bits.read(offset_slot) as usize;
            if offset > out.len() || offset == 0 {
                return None;
            }
            let take = length.min(out_len - out.len());
            for _ in 0..take {
                let b = out[out.len() - offset];
                out.push(b);
            }
        }
        Some(out)
    }
}
