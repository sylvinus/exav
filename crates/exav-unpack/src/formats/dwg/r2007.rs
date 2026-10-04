//! The R2007 file organisation (ODA spec chapter 5): a file header, a page
//! map and a section map in system pages, and named sections made of data
//! pages. Pages are Reed-Solomon coded (spec 5.13) and most are compressed
//! with an LZ77 variant of their own (spec 5.10).
//!
//! The codes are systematic: a page's bytes are read where the coding put
//! them, its parity is not used. The ODA File Converter does not correct
//! with it either: a file with two bytes flipped in one 255-byte block of a
//! data page, which the code could correct, fails its CRC there. The maps and the header are
//! checked by their CRCs (spec 5.12), the data pages by their checksums (spec
//! 5.4.1); a map or header that fails is taken from one of the copies the
//! file keeps.
//!
//! Nothing is allocated from a size the file gives before that size is
//! checked against what the file holds, or, for decompressed data, against
//! the byte budget the caller gives.

use super::r2004::Inflate;
use super::Error;

/// Spec 5.13: a codeword of 255 bytes, 239 of them data in system pages,
/// 251 in data pages.
const RS_N: usize = 255;
const SYSTEM_K: usize = 239;
const DATA_K: usize = 251;
/// Spec 5.2: the file header page at 0x80, three interleaved codewords.
const FILE_HEADER_AT: usize = 0x80;
const FILE_HEADER_PAGE: usize = 0x400;
const FILE_HEADER_BLOCKS: usize = 3;
/// The decompressed file header's size (spec 5.2).
const HEADER_FIELDS: usize = 0x110;
/// Page map offsets count from here (spec 5.2: "add 0x480").
const PAGES_BASE: u64 = 0x480;
/// The most one page may expand to. Writers use 0xF800 or a little more;
/// this only bounds the memory a damaged size can take.
const MAX_PAGE: u64 = 1 << 24;
/// A system page holds its data this many times at most: more would only
/// make a damaged factor repeat the CRC checks.
const MAX_COPIES: u64 = 64;

fn le32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le64(d: &[u8], at: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(8)?)?;
    let mut x = [0u8; 8];
    x.copy_from_slice(b);
    Some(u64::from_le_bytes(x))
}

fn align8(n: usize) -> usize {
    n.div_ceil(8).saturating_mul(8)
}

/// Spec 5.12.1: the normal CRC-64 (ECMA-182's polynomial, MSB first).
const CRC_NORMAL: [u64; 256] = {
    let mut t = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u64) << 56;
        let mut k = 0;
        while k < 8 {
            c = if c >> 63 != 0 {
                (c << 1) ^ 0x42F0_E1EB_A9EA_3693
            } else {
                c << 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Spec 5.12.2: the mirrored CRC-64. Its table is the reflected one of
/// 0x95AC9329AC4BC9B5 (the table's entry 0x80), not of ECMA-182's.
const CRC_MIRRORED: [u64; 256] = {
    let mut t = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x95AC_9329_AC4B_C9B5
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Spec 5.12: bytes go through the CRC 8 at a time in the order 6, 7, 4,
/// 5, 2, 3, 0, 1, and a shorter rest in the order of the spec's table (its
/// blocks of 4 taken in that table's order for 4). The checksum of spec
/// 5.4.1 takes them in the same order.
fn crc_order(data: &[u8], mut f: impl FnMut(u8)) {
    const REST: [&[usize]; 8] = [
        &[],
        &[0],
        &[0, 1],
        &[0, 1, 2],
        &[2, 3, 0, 1],
        &[2, 3, 0, 1, 4],
        &[2, 3, 0, 1, 4, 5],
        &[2, 3, 0, 1, 4, 5, 6],
    ];
    let (chunks, rest) = data.as_chunks::<8>();
    for c in chunks {
        for k in [6, 7, 4, 5, 2, 3, 0, 1] {
            f(c[k]);
        }
    }
    for &k in REST[rest.len()] {
        f(rest[k]);
    }
}

fn crc_normal(seed: u64, data: &[u8]) -> u64 {
    let mut c = seed;
    crc_order(data, |b| {
        c = CRC_NORMAL[usize::from(b ^ (c >> 56) as u8)] ^ (c << 8);
    });
    !c
}

fn crc_mirrored(seed: u64, data: &[u8]) -> u64 {
    let mut c = seed;
    crc_order(data, |b| {
        c = CRC_MIRRORED[usize::from(b ^ c as u8)] ^ (c >> 8);
    });
    c
}

/// Spec 5.12's UpdateSeed1.
fn seed1(seed: u64, len: usize) -> u64 {
    let s = seed
        .wrapping_add(len as u64)
        .wrapping_mul(0x343FD)
        .wrapping_add(0x269EC3);
    !(s | s.wrapping_mul(0x343FD << 32).wrapping_add(0x269EC3 << 32))
}

/// Spec 5.12's UpdateSeed2.
fn seed2(seed: u64, len: usize) -> u64 {
    let s = seed
        .wrapping_add(len as u64)
        .wrapping_mul(0x343FD)
        .wrapping_add(0x269EC3);
    !s.wrapping_mul((1 << 32) + 0x343FD)
        .wrapping_add((len as u64).wrapping_add(0x269EC3))
}

/// The data page checksum of spec 5.4.1, seed 0, over the page's data as
/// decompressed.
fn checksum(data: &[u8]) -> u32 {
    let seed = (data.len() as u64)
        .wrapping_mul(0x343FD)
        .wrapping_add(0x269EC3);
    let mut sum1 = (seed & 0xFFFF) as u32;
    let mut sum2 = ((seed >> 16) & 0xFFFF) as u32;
    for chunk in data.chunks(0x15B0) {
        crc_order(chunk, |b| {
            sum1 += u32::from(b);
            sum2 += sum1;
        });
        sum1 %= 0xFFF1;
        sum2 %= 0xFFF1;
    }
    (sum2 << 16) | (sum1 & 0xFFFF)
}

/// Spec 5.10.1: a literal run's bytes are stored in a shuffled order. For
/// each length to 32, the blocks (length, offset in the run) it is copied
/// as, in output order; a block of more than one byte is itself copied as a
/// run of its length. Runs longer than 32 go 32 at a time.
const SHUFFLE: [&[(usize, usize)]; 33] = [
    &[],
    &[(1, 0)],
    &[(1, 1), (1, 0)],
    &[(1, 2), (1, 1), (1, 0)],
    &[(1, 0), (1, 1), (1, 2), (1, 3)],
    &[(1, 4), (4, 0)],
    &[(1, 5), (4, 1), (1, 0)],
    &[(2, 5), (4, 1), (1, 0)],
    &[(4, 0), (4, 4)],
    &[(1, 8), (8, 0)],
    &[(1, 9), (8, 1), (1, 0)],
    &[(2, 9), (8, 1), (1, 0)],
    &[(4, 8), (8, 0)],
    &[(1, 12), (4, 8), (8, 0)],
    &[(1, 13), (4, 9), (8, 1), (1, 0)],
    &[(2, 13), (4, 9), (8, 1), (1, 0)],
    &[(8, 8), (8, 0)],
    &[(8, 9), (1, 8), (8, 0)],
    &[(1, 17), (16, 1), (1, 0)],
    &[(3, 16), (16, 0)],
    &[(4, 16), (16, 0)],
    &[(1, 20), (4, 16), (16, 0)],
    &[(2, 20), (4, 16), (16, 0)],
    &[(3, 20), (4, 16), (16, 0)],
    &[(8, 16), (16, 0)],
    &[(8, 17), (1, 16), (16, 0)],
    &[(1, 25), (8, 17), (1, 16), (16, 0)],
    &[(2, 25), (8, 17), (1, 16), (16, 0)],
    &[(4, 24), (8, 16), (16, 0)],
    &[(1, 28), (4, 24), (8, 16), (16, 0)],
    &[(2, 28), (4, 24), (8, 16), (16, 0)],
    &[(1, 30), (4, 26), (8, 18), (16, 2), (2, 0)],
    &[(16, 16), (16, 0)],
];

/// Copy `run` (at most 32 bytes) to `out` in spec 5.10.1's order. Blocks
/// are shorter than their run, so this recurses at most five deep.
fn unshuffle(run: &[u8], out: &mut Vec<u8>) {
    if let [b] = run {
        out.push(*b);
        return;
    }
    for &(len, at) in SHUFFLE.get(run.len()).copied().unwrap_or(&[]) {
        if let Some(block) = run.get(at..at + len) {
            unshuffle(block, out);
        }
    }
}

struct Inflater<'s> {
    src: &'s [u8],
    i: usize,
    out: Vec<u8>,
    limit: usize,
}

impl Inflater<'_> {
    fn byte(&mut self) -> Result<u8, Inflate> {
        let b = *self.src.get(self.i).ok_or(Inflate::Truncated)?;
        self.i += 1;
        Ok(b)
    }

    /// Spec 5.10.1's ReadLiteralLength.
    fn literal_length(&mut self, op: u8) -> Result<usize, Inflate> {
        let mut n = usize::from(op) + 8;
        if n == 0x17 {
            let b = self.byte()?;
            n += usize::from(b);
            if b == 0xFF {
                loop {
                    let w = usize::from(self.byte()?) | usize::from(self.byte()?) << 8;
                    n += w;
                    if w != 0xFFFF {
                        break;
                    }
                }
            }
        }
        Ok(n)
    }

    fn literal(&mut self, n: usize) -> Result<(), Inflate> {
        let end = self.i.checked_add(n).ok_or(Inflate::Truncated)?;
        let run = self.src.get(self.i..end).ok_or(Inflate::Truncated)?;
        if self.out.len() + n > self.limit {
            return Err(Inflate::TooLong);
        }
        for chunk in run.chunks(32) {
            unshuffle(chunk, &mut self.out);
        }
        self.i = end;
        Ok(())
    }

    /// Spec 5.10.2's ReadInstructions: the offset and length of a copy,
    /// and the byte whose low bits say what follows it.
    fn instruction(&mut self, op: u8) -> Result<(u8, usize, usize), Inflate> {
        Ok(match op >> 4 {
            0 => {
                let off = usize::from(self.byte()?);
                let next = self.byte()?;
                let len = usize::from(op & 0x0F) + 0x13 + usize::from((next >> 3) & 0x10);
                (next, (usize::from(next & 0x78) << 5) + 1 + off, len)
            }
            1 => {
                let off = usize::from(self.byte()?);
                let next = self.byte()?;
                let len = usize::from(op & 0x0F) + 3;
                (next, (usize::from(next & 0xF8) << 5) + 1 + off, len)
            }
            2 => {
                let mut off = usize::from(self.byte()?) | usize::from(self.byte()?) << 8;
                let mut len = usize::from(op & 7);
                let next;
                if op & 8 == 0 {
                    next = self.byte()?;
                    len += usize::from(next & 0xF8);
                } else {
                    off += 1;
                    len += usize::from(self.byte()?) << 3;
                    next = self.byte()?;
                    len += (usize::from(next & 0xF8) << 8) + 0x100;
                }
                (next, off, len)
            }
            _ => {
                let next = self.byte()?;
                let off = (usize::from(next & 0xF8) << 1) + usize::from(op & 0x0F) + 1;
                (next, off, usize::from(op >> 4))
            }
        })
    }

    /// A copy from `off` bytes back; it may overlap what it writes.
    fn copy(&mut self, off: usize, len: usize) -> Result<(), Inflate> {
        if off == 0 || off > self.out.len() {
            return Err(Inflate::BadOffset);
        }
        if self.out.len() + len > self.limit {
            return Err(Inflate::TooLong);
        }
        let from = self.out.len() - off;
        for k in 0..len {
            let b = self.out[from + k];
            self.out.push(b);
        }
        Ok(())
    }
}

/// Expand spec 5.10's LZ77 variant, at most `limit` bytes.
///
/// Spec 5.10.1's table gives a literal run's blocks; a block of 2, 3 or 16
/// bytes is not a plain copy but a run of that length, shuffled the same
/// way (with plain copies the section map's names come out as `Ap\0p`
/// where `AppInfo` is; with runs every page of the corpus's R2007 files
/// matches its checksum).
pub(super) fn decompress(src: &[u8], limit: usize) -> Result<Vec<u8>, Inflate> {
    let mut z = Inflater {
        src,
        i: 0,
        out: Vec::with_capacity(limit.min(src.len().saturating_mul(8))),
        limit,
    };
    let mut op = z.byte()?;
    let mut length = 0;
    // A first opcode of 0x2X skips two bytes; the next one's low bits are
    // the first literal's length.
    if op >> 4 == 2 {
        z.i = 3;
        length = usize::from(z.byte()? & 7);
    }
    while z.i < src.len() {
        if length == 0 {
            length = z.literal_length(op)?;
        }
        z.literal(length)?;
        if z.i >= src.len() {
            break;
        }
        op = z.byte()?;
        let (mut next, mut off, mut len) = z.instruction(op)?;
        loop {
            z.copy(off, len)?;
            length = usize::from(next & 7);
            if length != 0 || z.i >= src.len() {
                break;
            }
            op = z.byte()?;
            if op >> 4 == 0 {
                break;
            }
            if op >> 4 == 0x0F {
                op &= 0x0F;
            }
            (next, off, len) = z.instruction(op)?;
        }
    }
    Ok(z.out)
}

/// `len` data bytes from `from` of Reed-Solomon codewords interleaved
/// `blocks` ways (spec 5.13.2): byte `i` of block `j` is at `j + blocks * i`
/// and a block's first `k` bytes are its data.
fn deinterleave(raw: &[u8], blocks: usize, k: usize, from: usize, len: usize) -> Option<Vec<u8>> {
    let end = from.checked_add(len)?;
    if end > blocks.checked_mul(k)? || raw.len() < blocks.checked_mul(RS_N)? {
        return None;
    }
    Some((from..end).map(|t| raw[t / k + blocks * (t % k)]).collect())
}

/// The decoded file header (spec 5.2), the fields a reader needs.
#[derive(Clone, Copy, Debug)]
struct FileHeader {
    pages_map: SystemPage,
    /// Offsets from 0x480: the page map and its copy.
    pages_map_offsets: [u64; 2],
    sections_map: SystemPage,
    /// Page numbers: the section map and its copy.
    sections_map_ids: [u64; 2],
    crc_ok: bool,
}

/// What a system page's data is checked and expanded by (spec 5.3).
#[derive(Clone, Copy, Debug)]
struct SystemPage {
    compressed_size: u64,
    size: u64,
    factor: u64,
    compressed_crc: u64,
    crc: u64,
    seed: u64,
}

/// The file header from its page (spec 5.2): three codewords interleaved,
/// whose data is a block repeated as often as it fits: a check CRC and
/// value, the compressed data's CRC and size, then the data. The first copy
/// whose header CRC matches is taken, else the first that expands.
fn file_header(page: &[u8]) -> Option<FileHeader> {
    let data = deinterleave(
        page,
        FILE_HEADER_BLOCKS,
        SYSTEM_K,
        0,
        FILE_HEADER_BLOCKS * SYSTEM_K,
    )?;
    let mut fallback = None;
    let mut at = 0usize;
    while let Some(len) = le32(&data, at + 0x18) {
        let len = len as i32;
        let n = len.unsigned_abs() as usize;
        let Some(body) = (at + 0x20)
            .checked_add(n)
            .and_then(|end| data.get(at + 0x20..end))
        else {
            break;
        };
        let fields = if len < 0 {
            Some(body.to_vec())
        } else {
            decompress(body, HEADER_FIELDS).ok()
        };
        if let Some(h) = fields.and_then(|f| header_fields(&f)) {
            if h.crc_ok {
                return Some(h);
            }
            fallback.get_or_insert(h);
        }
        at = align8(at + 0x20 + n);
    }
    fallback
}

/// The fields of the decompressed file header (spec 5.2's second table),
/// its CRC (5.2.1.2: normal CRC-64, seed UpdateSeed2(0)) checked.
fn header_fields(h: &[u8]) -> Option<FileHeader> {
    let h = h.get(..HEADER_FIELDS)?;
    let f = |at: usize| le64(h, at);
    let mut zeroed = h.to_vec();
    zeroed[0x108..0x110].fill(0);
    let crc_ok = crc_normal(seed2(0, zeroed.len()), &zeroed) == f(0x108)?;
    // Without its CRC, a header is one if it gives the size every file has.
    if !crc_ok && f(0)? != 0x70 {
        return None;
    }
    let seed = f(0xF0)?;
    Some(FileHeader {
        pages_map: SystemPage {
            compressed_size: f(0x50)?,
            size: f(0x58)?,
            factor: f(0x18)?,
            compressed_crc: f(0x10)?,
            crc: f(0x80)?,
            seed,
        },
        pages_map_offsets: [f(0x38)?, f(0x28)?],
        sections_map: SystemPage {
            compressed_size: f(0xB0)?,
            size: f(0xC8)?,
            factor: f(0xD8)?,
            compressed_crc: f(0xD0)?,
            crc: f(0xA8)?,
            seed,
        },
        sections_map_ids: [f(0xC0)?, f(0xB8)?],
        crc_ok,
    })
}

/// The file header at 0x80, else its copy in the last 0x400 bytes (spec
/// 5.2.1.8): the first whose CRC matches, else the first that decodes.
fn find_file_header(data: &[u8]) -> Option<FileHeader> {
    let first = data
        .get(FILE_HEADER_AT..FILE_HEADER_AT + FILE_HEADER_PAGE)
        .and_then(file_header);
    if first.is_some_and(|h| h.crc_ok) {
        return first;
    }
    let copy = data
        .len()
        .checked_sub(FILE_HEADER_PAGE)
        .filter(|at| *at > FILE_HEADER_AT)
        .and_then(|at| data.get(at..))
        .and_then(file_header);
    match (first, copy) {
        (_, Some(c)) if c.crc_ok => Some(c),
        (Some(f), _) => Some(f),
        (None, c) => c,
    }
}

/// Whether `data` has an R2007 file header that decodes, at 0x80 or as the
/// copy at its end (when `data` is the whole file).
pub(super) fn has_file_header(data: &[u8]) -> bool {
    find_file_header(data).is_some()
}

/// A page of the page map: its number and where it is.
#[derive(Clone, Copy, Debug)]
struct Page {
    id: u64,
    address: u64,
}

/// A page of a section (spec 5.2's section map).
#[derive(Clone, Copy, Debug)]
struct PageRef {
    offset: u64,
    id: u64,
    size: u64,
    compressed_size: u64,
    checksum: u64,
}

/// A data section of the section map.
#[derive(Clone, Debug)]
pub(super) struct Section {
    name: String,
    size: u64,
    max_size: u64,
    encrypted: u64,
    /// 4: the codewords are interleaved; 1: the data comes first.
    encoding: u64,
    pages: Vec<PageRef>,
}

impl Section {
    pub(super) fn is_encrypted(&self) -> bool {
        self.encrypted == 1
    }
}

/// The page map and the section map of an R2007 file.
pub(super) struct Container<'a> {
    data: &'a [u8],
    /// Sorted by number.
    pages: Vec<Page>,
    sections: Vec<Section>,
    /// Bytes decompressing may still produce.
    budget: u64,
}

impl<'a> Container<'a> {
    /// Read the file header and the two maps. `budget` bounds every byte
    /// decompressed from here on, the maps' included.
    pub(super) fn open(
        data: &'a [u8],
        budget: u64,
        problems: &mut Vec<String>,
    ) -> Result<Container<'a>, Error> {
        let fh = find_file_header(data).ok_or(Error::NotDwg)?;
        if !fh.crc_ok {
            problems.push("the file header's CRC does not match".into());
        }
        let mut c = Container {
            data,
            pages: Vec::new(),
            sections: Vec::new(),
            budget,
        };
        let addresses = fh.pages_map_offsets.map(|o| o.saturating_add(PAGES_BASE));
        let map = c.system_page(addresses, fh.pages_map, "section page map", problems)?;
        c.read_page_map(&map);
        let addresses = fh
            .sections_map_ids
            .map(|id| c.page(id).map_or(u64::MAX, |p| p.address));
        let map = c.system_page(addresses, fh.sections_map, "section map", problems)?;
        c.read_section_map(&map, problems);
        Ok(c)
    }

    fn take_budget(&mut self, n: u64) -> bool {
        if n > self.budget {
            return false;
        }
        self.budget -= n;
        true
    }

    fn page(&self, id: u64) -> Option<Page> {
        let i = self.pages.binary_search_by_key(&id, |p| p.id).ok()?;
        self.pages.get(i).copied()
    }

    /// A system page (spec 5.3) at the first of `addresses` whose data
    /// passes its CRCs, else at the first that expands: codewords
    /// interleaved over the data repeated `factor` times, each copy padded
    /// to 8 bytes; the copies are tried in turn.
    fn system_page(
        &mut self,
        addresses: [u64; 2],
        p: SystemPage,
        what: &str,
        problems: &mut Vec<String>,
    ) -> Result<Vec<u8>, Error> {
        let damaged = || Error::Damaged(format!("the {what} is unreadable"));
        if p.size > MAX_PAGE || p.compressed_size > MAX_PAGE {
            return Err(damaged());
        }
        let (packed, size) = (p.compressed_size as usize, p.size as usize);
        let aligned = align8(packed);
        let factor = p.factor.clamp(1, MAX_COPIES) as usize;
        let blocks = (factor * aligned).div_ceil(SYSTEM_K);
        let mut first = None;
        for address in addresses {
            let Some(raw) = usize::try_from(address)
                .ok()
                .and_then(|at| self.data.get(at..at.checked_add(blocks * RS_N)?))
            else {
                continue;
            };
            for copy in 0..factor {
                let Some(body) = deinterleave(raw, blocks, SYSTEM_K, copy * aligned, packed) else {
                    break;
                };
                let body_ok = crc_mirrored(seed1(p.seed, packed), &body) == p.compressed_crc;
                if !body_ok && first.is_some() {
                    continue;
                }
                // Every copy expanded is charged: a damaged page could
                // otherwise be expanded once per copy for free.
                if !self.take_budget(p.size) {
                    return Err(Error::LimitExceeded(format!(
                        "the {what} declares {} bytes",
                        p.size
                    )));
                }
                let out = if packed < size {
                    decompress(&body, size).ok()
                } else {
                    body.get(..size).map(<[u8]>::to_vec)
                };
                let Some(out) = out.filter(|o| o.len() == size) else {
                    continue;
                };
                if body_ok && crc_mirrored(seed1(p.seed, size), &out) == p.crc {
                    return Ok(out);
                }
                first.get_or_insert(out);
            }
        }
        let out = first.ok_or_else(damaged)?;
        problems.push(format!("the {what} fails its CRC"));
        Ok(out)
    }

    /// The page map (spec 5.2): pairs of a size and a page number; pages
    /// follow each other from 0x480. A negative number stands for its
    /// absolute value, as the spec's loop has it.
    fn read_page_map(&mut self, map: &[u8]) {
        let mut address = PAGES_BASE;
        for pair in map.as_chunks::<16>().0 {
            let size = le64(pair, 0).unwrap_or(0);
            let id = le64(pair, 8).unwrap_or(0) as i64;
            self.pages.push(Page {
                id: id.unsigned_abs(),
                address,
            });
            address = address.saturating_add(size);
        }
        // Numbers are unique; the first of a repeated one is kept.
        self.pages.sort_by_key(|p| p.id);
        self.pages.dedup_by_key(|p| p.id);
    }

    /// The section map (spec 5.2): each section's eight longs, its name
    /// (UTF-16; the length counts bytes, the terminator included, not
    /// characters as the spec has it), then its pages' seven longs each.
    fn read_section_map(&mut self, map: &[u8], problems: &mut Vec<String>) {
        let mut at = 0usize;
        while at + 64 <= map.len() {
            let f = |k: usize| le64(map, at + k * 8).unwrap_or(0);
            let (size, max_size, encrypted, name_len, encoding, count) =
                (f(0), f(1), f(2), f(4), f(6), f(7));
            at += 64;
            let Some(raw_name) = usize::try_from(name_len)
                .ok()
                .and_then(|n| map.get(at..at.checked_add(n)?))
            else {
                problems.push("the section map is cut short".into());
                return;
            };
            at += raw_name.len();
            let units: Vec<u16> = raw_name
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|u| *u != 0)
                .collect();
            // A page takes 56 bytes: the count cannot be more.
            if count > ((map.len() - at) / 56) as u64 {
                problems.push("the section map is cut short".into());
                return;
            }
            let mut pages = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let g = |k: usize| le64(map, at + k * 8).unwrap_or(0);
                pages.push(PageRef {
                    offset: g(0),
                    id: g(2),
                    size: g(3),
                    compressed_size: g(4),
                    checksum: g(5),
                });
                at += 56;
            }
            self.sections.push(Section {
                name: String::from_utf16_lossy(&units),
                size,
                max_size,
                encrypted,
                encoding,
                pages,
            });
        }
    }

    pub(super) fn section_info(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The data of a named section, its pages decoded, decompressed and
    /// joined, the pages a writer left out (they hold zeros) put back;
    /// `None` when the file has no such section. What cannot be read is
    /// said in `problems` and cut short.
    pub(super) fn section(
        &mut self,
        name: &str,
        problems: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(s) = self.section_info(name).cloned() else {
            return Ok(None);
        };
        // Pages of zeros are left out, but a section of more of them than
        // of written pages is not one a writer makes: it would only make
        // this reader allocate. Writers make pages of up to the section's
        // page size, AutoCAD a little more.
        let largest = s.pages.iter().map(|p| p.size).fold(s.max_size, u64::max);
        let most = (s.pages.len() as u64 + 1).saturating_mul(largest.min(MAX_PAGE));
        if s.size > most {
            problems.push(format!(
                "section {name} declares {} bytes, more than its pages hold",
                s.size
            ));
            return Ok(Some(Vec::new()));
        }
        let Some(size) = usize::try_from(s.size)
            .ok()
            .filter(|_| self.take_budget(s.size))
        else {
            return Err(Error::LimitExceeded(format!(
                "section {name} declares {} bytes",
                s.size
            )));
        };
        let mut out: Vec<u8> = Vec::new();
        for r in &s.pages {
            if out.len() >= size && size > 0 {
                problems.push(format!("section {name} has pages past its end"));
                break;
            }
            let Some(start) = usize::try_from(r.offset).ok().filter(|v| *v <= size) else {
                problems.push(format!("a page of {name} starts past the section's end"));
                break;
            };
            if start < out.len() {
                problems.push(format!("the pages of {name} overlap"));
                break;
            }
            out.resize(start, 0);
            match self.data_page(&s, r, problems)? {
                Some(mut page) => {
                    page.truncate(size - start);
                    out.extend_from_slice(&page);
                }
                None => {
                    problems.push(format!("a page of section {name} is unreadable"));
                    break;
                }
            }
        }
        out.resize(size, 0);
        Ok(Some(out))
    }

    /// One data page (spec 5.4): the data, padded to 8 bytes, Reed-Solomon
    /// coded in blocks of 251, interleaved or with all the parity after the
    /// data; compressed when its compressed size is the smaller.
    ///
    /// What a page holds and expands to is taken from the budget too: page
    /// references may repeat a page, so without it a small file could have
    /// one page checked and expanded over and over.
    fn data_page(
        &mut self,
        s: &Section,
        r: &PageRef,
        problems: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let over = || Error::LimitExceeded("the pages of a section".into());
        let Some(page) = self.page(r.id) else {
            return Ok(None);
        };
        if r.size > MAX_PAGE || r.compressed_size > MAX_PAGE {
            return Ok(None);
        }
        let (packed, size) = (r.compressed_size as usize, r.size as usize);
        let blocks = align8(packed).div_ceil(DATA_K);
        let stored = if s.encoding == 4 {
            blocks * RS_N
        } else {
            packed
        };
        let Some(raw) = usize::try_from(page.address)
            .ok()
            .and_then(|at| self.data.get(at..at.checked_add(stored)?))
        else {
            return Ok(None);
        };
        if !self.take_budget(stored as u64) {
            return Err(over());
        }
        let body = if s.encoding == 4 {
            match deinterleave(raw, blocks, DATA_K, 0, packed) {
                Some(b) => b,
                None => return Ok(None),
            }
        } else {
            raw.get(..packed).unwrap_or(&[]).to_vec()
        };
        let out = if packed < size {
            let most = size.min(usize::try_from(self.budget).unwrap_or(usize::MAX));
            match decompress(&body, most) {
                Ok(out) => out,
                Err(_) => return Ok(None),
            }
        } else {
            body.get(..size).unwrap_or(&body).to_vec()
        };
        if out.len() != size || u64::from(checksum(&out)) != r.checksum {
            problems.push(format!(
                "the page at {:#X} fails its checksum",
                page.address
            ));
        }
        if !self.take_budget(out.len() as u64) {
            return Err(over());
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_tables_are_the_specifications() {
        // Spec 5.12.1 and 5.12.2, the second and the last entries.
        assert_eq!(CRC_NORMAL[1], 0x42F0_E1EB_A9EA_3693);
        assert_eq!(CRC_NORMAL[255], 0x9AFC_E626_CE85_B507);
        assert_eq!(CRC_MIRRORED[1], 0x7AD8_70C8_3035_8979);
        assert_eq!(CRC_MIRRORED[255], 0x29B7_D047_EFEC_8728);
    }

    /// A first literal: a first opcode of 0x2X gives its length in the
    /// fourth byte (up to 7), any other opcode is the length less 8.
    fn literal(run: &[u8]) -> Vec<u8> {
        let mut src = if run.len() < 8 {
            vec![0x20, 0, 0, run.len() as u8]
        } else {
            vec![(run.len() - 8) as u8]
        };
        src.extend_from_slice(run);
        decompress(&src, 1000).unwrap()
    }

    /// Spec 5.10.1's table, its blocks of 2, 3 and 16 bytes taken as runs
    /// of their own (so reversed, reversed, and their halves swapped).
    #[test]
    fn literal_runs_come_out_in_the_specifications_order() {
        let run = |n: u8| (0..n).collect::<Vec<u8>>();
        assert_eq!(literal(&run(1)), [0]);
        assert_eq!(literal(&run(2)), [1, 0]);
        assert_eq!(literal(&run(3)), [2, 1, 0]);
        assert_eq!(literal(&run(4)), [0, 1, 2, 3]);
        // 2 [5], 4 [1], 1 [0].
        assert_eq!(literal(&run(7)), [6, 5, 1, 2, 3, 4, 0]);
        assert_eq!(literal(&run(8)), run(8));
        assert_eq!(literal(&run(10)), [9, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        assert_eq!(
            literal(&run(16)),
            [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7]
        );
        // 1 [17], 16 [1], 1 [0]: the 16 bytes from 1 with their halves
        // swapped.
        assert_eq!(
            literal(&run(18)),
            [17, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 0]
        );
        let swapped16 =
            |from: u8| -> Vec<u8> { (from + 8..from + 16).chain(from..from + 8).collect() };
        // 16 [16], 16 [0].
        let mut want = swapped16(16);
        want.extend(swapped16(0));
        assert_eq!(literal(&run(32)), want);
        // Opcode 0x0F: 0x17 plus the next byte. 40 bytes: 32, then 8 as is.
        let mut src = vec![0x0F, 40 - 0x17];
        src.extend(run(40));
        want.extend(32..40);
        assert_eq!(decompress(&src, 1000).unwrap(), want);
    }

    /// A literal of `abcdefgh` (a run of 8 is stored as is), then `ops`.
    fn after_eight(ops: &[u8]) -> Result<Vec<u8>, Inflate> {
        let mut src = vec![0x00];
        src.extend_from_slice(b"abcdefgh");
        src.extend_from_slice(ops);
        decompress(&src, 1000)
    }

    /// What copying `len` bytes from `off` back onto `out` gives, a byte
    /// at a time.
    fn copied(out: &[u8], off: usize, len: usize) -> Vec<u8> {
        let mut v = out.to_vec();
        for _ in 0..len {
            v.push(v[v.len() - off]);
        }
        v
    }

    #[test]
    fn copies_take_their_offset_and_length_from_spec_5_10_2() {
        // 0x41: 4 bytes from (1 + 0 + 1) = 2 back; the next byte's low bits
        // (0) say no literal follows.
        let ghgh = copied(b"abcdefgh", 2, 4);
        assert_eq!(after_eight(&[0x41, 0x00]).unwrap(), ghgh);
        // Its low bits 2: a literal of two bytes (reversed) follows.
        let mut want = ghgh.clone();
        want.extend_from_slice(b"xy");
        assert_eq!(after_eight(&[0x41, 0x02, b'y', b'x']).unwrap(), want);
        // 0x12: (2 + 3) bytes from (3 + 1) back.
        assert_eq!(
            after_eight(&[0x12, 0x03, 0x00]).unwrap(),
            copied(b"abcdefgh", 4, 5)
        );
        // After a copy, 0xF1 is opcode 0x01: (1 + 0x13) bytes from (7 + 1)
        // back.
        assert_eq!(
            after_eight(&[0x41, 0x00, 0xF1, 0x07, 0x00]).unwrap(),
            copied(&ghgh, 8, 20)
        );
        // 0x23: an offset of two bytes (5), (3 + (0x08 & 0xF8)) bytes.
        assert_eq!(
            after_eight(&[0x41, 0x00, 0x23, 0x05, 0x00, 0x08]).unwrap(),
            copied(&ghgh, 5, 11)
        );
        // 0x28: the offset plus one (8), (0 + (1 << 3) + 0x100) bytes.
        assert_eq!(
            after_eight(&[0x41, 0x00, 0x28, 0x07, 0x00, 0x01, 0x00]).unwrap(),
            copied(&ghgh, 8, 0x108)
        );
    }

    #[test]
    fn bad_copies_and_short_input_are_errors() {
        // From (0xF8 << 1) + 1 + 1 back, past the start.
        assert_eq!(after_eight(&[0x41, 0xF8]), Err(Inflate::BadOffset));
        // An offset of 0.
        assert_eq!(
            after_eight(&[0x41, 0x00, 0x23, 0x00, 0x00, 0x08]),
            Err(Inflate::BadOffset)
        );
        assert_eq!(after_eight(&[0x12, 0x03]), Err(Inflate::Truncated));
        assert_eq!(decompress(&[0x00, 1, 2, 3], 100), Err(Inflate::Truncated));
        assert_eq!(decompress(&[], 100), Err(Inflate::Truncated));
        let mut src = vec![0x00];
        src.extend_from_slice(b"abcdefgh");
        assert_eq!(decompress(&src, 7), Err(Inflate::TooLong));
        src.extend_from_slice(&[0x41, 0x00]);
        assert_eq!(decompress(&src, 11), Err(Inflate::TooLong));
    }

    /// Spec 5.13.2: byte `i` of block `j` of `n` interleaved blocks is at
    /// `j + n * i`; a block's data is its first `k` bytes.
    #[test]
    fn interleaved_codewords_give_their_data_in_block_order() {
        let mut raw = vec![0u8; 3 * RS_N];
        for j in 0..3 {
            for i in 0..RS_N {
                raw[j + 3 * i] = (j * 100 + i) as u8;
            }
        }
        let want: Vec<u8> = (0..3)
            .flat_map(|j| (0..SYSTEM_K).map(move |i| (j * 100 + i) as u8))
            .collect();
        assert_eq!(deinterleave(&raw, 3, SYSTEM_K, 0, want.len()), Some(want));
        assert_eq!(
            deinterleave(&raw, 3, SYSTEM_K, SYSTEM_K, 3),
            Some(vec![100, 101, 102])
        );
        assert_eq!(deinterleave(&raw, 3, SYSTEM_K, 3 * SYSTEM_K - 1, 2), None);
        assert_eq!(deinterleave(&raw[..RS_N * 3 - 1], 3, SYSTEM_K, 0, 1), None);
    }

    /// Spec 5.4.1: the sums start from the seed the length gives, and the
    /// bytes of a 4-byte rest go 2, 3, 0, 1.
    #[test]
    fn the_page_checksum_is_the_specifications() {
        assert_eq!(checksum(&[]), 0x0026_9EC3);
        // Seed 0x33AEB7; in order the bytes would give 0xBB41AEC1.
        assert_eq!(checksum(&[1, 2, 3, 4]), 0xBB49_AEC1);
    }
}
