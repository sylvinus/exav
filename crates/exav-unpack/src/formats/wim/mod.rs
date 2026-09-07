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
//! **Every resource is checked against the SHA-1 the image records for it.** A
//! chunk decoder that is subtly wrong does not fail — it produces plausible
//! bytes that are not the file, and a signature that fails to match those reads
//! exactly like a clean file. The hash is what separates "decoded" from
//! "decoded correctly", so a resource that fails it is reported rather than
//! handed over.

use std::collections::HashMap;

use crate::{Budget, Entry, LimitHit, Sink};

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
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

fn le_u64(d: &[u8], off: usize) -> u64 {
    d.get(off..off + 8)
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
    for i in 0..7 {
        size |= (data.get(off + i).copied().unwrap_or(0) as u64) << (i * 8);
    }
    Resource {
        size_in_wim: size,
        flags: data.get(off + 7).copied().unwrap_or(0),
        offset: le_u64(data, off + 8),
        original_size: le_u64(data, off + 16),
        hash: [0; HASH_LEN],
    }
}

fn sha1_of(data: &[u8]) -> [u8; HASH_LEN] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; HASH_LEN];
    r.copy_from_slice(&out);
    r
}

/// Decompress one resource. `Err` names a reason worth reporting; `Ok` bytes are
/// still unverified until checked against the recorded hash.
fn read_resource(
    data: &[u8],
    res: &Resource,
    codec: Codec,
    chunk_size: u32,
    budget: &mut Budget,
) -> Result<Vec<u8>, &'static str> {
    let start = res.offset as usize;
    let end = start.saturating_add(res.size_in_wim as usize);
    let raw = data
        .get(start..end)
        .ok_or("WIM resource lies outside the image")?;

    if res.flags & RESOURCE_COMPRESSED == 0 {
        return Ok(raw.to_vec());
    }
    if codec == Codec::Lzms {
        return Err("WIM LZMS-compressed resource");
    }
    let cap = budget.limits.max_buffer_bytes;
    if res.original_size > cap {
        return Err("WIM resource exceeds max-buffer");
    }
    let chunk = chunk_size.max(1) as usize;
    let n_chunks = (res.original_size as usize).div_ceil(chunk).max(1);

    // The chunk table gives the start of chunks 1..n-1 relative to the end of
    // the table; chunk 0 always starts there. Entries are u32 unless the
    // uncompressed resource is over 4 GiB.
    let wide = res.original_size > u32::MAX as u64;
    let entry = if wide { 8 } else { 4 };
    let table_len = (n_chunks - 1) * entry;
    let table = raw.get(..table_len).ok_or("WIM chunk table is truncated")?;
    let body = &raw[table_len..];

    let chunk_start = |i: usize| -> usize {
        if i == 0 {
            0
        } else if wide {
            le_u64(table, (i - 1) * 8) as usize
        } else {
            le_u32(table, (i - 1) * 4) as usize
        }
    };

    let mut out = Vec::with_capacity(res.original_size as usize);
    for i in 0..n_chunks {
        let s = chunk_start(i);
        let e = if i + 1 < n_chunks {
            chunk_start(i + 1)
        } else {
            body.len()
        };
        let Some(cdata) = body.get(s..e.max(s)) else {
            return Err("WIM chunk lies outside its resource");
        };
        let want = chunk.min(res.original_size as usize - out.len());
        // A chunk that did not compress is stored verbatim, and is then exactly
        // as long as what it decodes to.
        if cdata.len() >= want {
            out.extend_from_slice(&cdata[..want]);
            continue;
        }
        let decoded = match codec {
            Codec::Xpress => xpress::decompress(cdata, want).ok_or("WIM XPRESS chunk")?,
            Codec::Lzx => lzx::decompress(cdata, want).ok_or("WIM LZX chunk")?,
            // An uncompressed image should have had the flag clear; if a
            // resource claims compression anyway there is nothing to decode it
            // with.
            Codec::None | Codec::Lzms => return Err("WIM resource names no chunk codec"),
        };
        out.extend_from_slice(&decoded);
    }
    out.truncate(res.original_size as usize);
    Ok(out)
}

mod lzx;

pub(crate) fn extract_wim<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !crate::formats::sniff::is(data, crate::Format::Wim) {
        return Ok(None);
    }
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
    let ts = table_res.offset as usize;
    let te = ts.saturating_add(table_res.size_in_wim as usize);
    let Some(table) = data.get(ts..te) else {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<wim-offset-table>".to_string(),
                0,
                false,
                "WIM offset table lies outside the image",
            ),
            budget,
        ));
    };

    let mut resources: Vec<Resource> = Vec::new();
    for i in 0..(table.len() / TABLE_ENTRY_LEN).min(MAX_RESOURCES) {
        let o = i * TABLE_ENTRY_LEN;
        let mut r = resource_header(table, o);
        if let Some(h) = table.get(o + 30..o + 30 + HASH_LEN) {
            r.hash.copy_from_slice(h);
        }
        resources.push(r);
    }
    if table.len() / TABLE_ENTRY_LEN > MAX_RESOURCES {
        budget.count_entry()?;
        if let Some(r) = visit(
            Entry::unsupported(
                format!("<wim-resources-beyond-{MAX_RESOURCES}>"),
                0,
                false,
                "too many WIM resources to enumerate them all",
            ),
            budget,
        ) {
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
        if let Ok(meta) = read_resource(data, res, codec, chunk_size, budget) {
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
            if let Some(r) = visit(
                Entry::unsupported(
                    name,
                    res.size_in_wim,
                    false,
                    "WIM resource continues in another part of a spanned image",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }

        budget.count_entry()?;
        let decoded = read_resource(data, res, codec, chunk_size, budget);
        let bytes = match decoded {
            // The image records a SHA-1 per resource. A chunk codec that is
            // subtly wrong yields plausible bytes rather than an error, so this
            // is the only thing distinguishing content from garbage.
            Ok(b) if sha1_of(&b) == res.hash => b,
            Ok(_) => {
                if let Some(r) = visit(
                    Entry::unsupported(
                        name,
                        res.size_in_wim,
                        false,
                        "WIM resource did not match its recorded SHA-1 after decoding",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            Err(reason) => {
                if let Some(r) = visit(
                    Entry::unsupported(name, res.size_in_wim, false, reason),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        let cap = budget.reserve()?;
        if bytes.len() as u64 > cap {
            return Err(LimitHit::new(format!("wim member '{name}' exceeds budget")));
        }
        budget.commit(bytes.len() as u64);
        if let Some(r) = visit(Entry::new(name, bytes), budget) {
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
    let root = sec_len.next_multiple_of(8);
    let mut stack = vec![(root, String::new())];
    let mut walked = 0usize;

    while let Some((mut off, prefix)) = stack.pop() {
        loop {
            walked += 1;
            if walked > MAX_DENTRIES {
                return;
            }
            let len = le_u64(meta, off) as usize;
            if len < DENTRY_NAME_OFF || off + len > meta.len() {
                break; // an end-of-directory marker is a zero length
            }
            let attributes = le_u32(meta, off + 8);
            let subdir = le_u64(meta, off + 16) as usize;
            let name_len = le_u16(meta, off + DENTRY_NAME_LEN_OFF) as usize;
            let name_at = off + DENTRY_NAME_OFF;
            let name = meta
                .get(name_at..name_at + name_len)
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
            } else if let Some(h) = meta.get(off + 64..off + 64 + HASH_LEN) {
                let mut hash = [0u8; HASH_LEN];
                hash.copy_from_slice(h);
                out.entry(hash).or_insert(path);
            }
            // Dentries are padded to an 8-byte boundary.
            off += len.next_multiple_of(8);
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
