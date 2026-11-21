//! decmpfs, the transparent compression macOS applies to files, decoded.
//!
//! A compressed file's data fork is empty. Its bytes are in the
//! `com.apple.decmpfs` attribute after a 16-byte header, or, for the types that
//! do not fit there, in the file's resource fork (an attribute of its own on
//! APFS, `com.apple.ResourceFork`). Both filesystems keep the same attribute
//! and the same fork, so one decoder serves `formats/hfsplus` and
//! `formats/apfs`.
//!
//! The header is little-endian: `cmpf`, the type, the uncompressed size. The
//! types and their layouts are the ones libarchive (zlib) and apfs-fuse
//! (the rest) read; Apple documents type 1 only.
//!
//! ```text
//! type  codec   payload
//!    1  none    attribute, as is
//!    3  zlib    attribute (a first byte of 0xFF marks stored bytes)
//!    7  LZVN    attribute (a first byte of 0x06 marks stored bytes)
//!    9  none    attribute, behind a 0xCC byte
//!   11  LZFSE   attribute
//!    4  zlib    resource fork: a table of (offset, length) per block
//!    8  LZVN    resource fork: a table of block offsets
//!   10  none    resource fork: as 8, a marker byte before each block
//!   12  LZFSE   resource fork: as 8
//! ```
//!
//! A file is cut in blocks of 64 KiB, each coded alone. Types 13 and 14
//! (LZBITMAP) and the dataless types, whose content is not on the volume,
//! are reported.
//!
//! A file whose bytes are in the resource fork is read a block at a time: the
//! table of the fork is read in a window, each block is read from the fork and
//! decoded alone, and what is held is one block coded, one block decoded and a
//! window of the table, however long the file is. One past the buffer limit is
//! handed over as it is read. A file whose bytes are in the attribute is one
//! unit of at most the attribute's size coded, held whole when it decodes to at
//! most the buffer limit, and reported past it.

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use super::vol::{Fill, Got, Step, Vol, be32, le32, le64, read_file};

/// The attribute holding the header, and on APFS the one holding the fork.
pub(crate) const ATTR: &str = "com.apple.decmpfs";
pub(crate) const RESOURCE_FORK_ATTR: &str = "com.apple.ResourceFork";

/// The file flag (`UF_COMPRESSED`) that marks a compressed file. macOS reads
/// the attribute only where it is set, so it decides here too.
pub(crate) const COMPRESSED_FLAG: u32 = 0x20;

const MAGIC: u32 = 0x636d_7066; // "cmpf"
const HEADER: usize = 16;
const BLOCK: usize = 0x1_0000;

/// How much of a fork's table is read at a time.
const TABLE_WINDOW: usize = 1 << 14;

/// The header of a `com.apple.decmpfs` attribute.
pub(crate) struct Header {
    pub(crate) kind: u32,
    /// The size of the file once decompressed.
    pub(crate) size: u64,
}

pub(crate) fn header(attr: &[u8]) -> Option<Header> {
    (attr.len() >= HEADER && le32(attr, 0) == MAGIC).then(|| Header {
        kind: le32(attr, 4),
        size: le64(attr, 8),
    })
}

/// Whether a type keeps its bytes in the resource fork.
pub(crate) fn in_fork(kind: u32) -> bool {
    matches!(kind, 4 | 8 | 10 | 12 | 14)
}

/// A resource fork, read where the table of a compressed file says.
pub(crate) trait Fork {
    /// The fork's size.
    fn size(&self) -> u64;

    /// Append `len` bytes of the fork from `off` to `out`. False when the
    /// fork has not all of them or the volume does not give them; what was
    /// appended before that may stay.
    fn read(&self, v: &mut Vol, off: u64, len: usize, out: &mut Vec<u8>) -> bool;
}

const DAMAGED: &str = "compressed file (decmpfs) with a damaged attribute";
const NO_FORK: &str = "compressed file (decmpfs) whose resource fork is missing";
const NOT_READ: &str = "compressed file (decmpfs) of a type exav does not read";
const BAD: &str = "compressed file (decmpfs) that did not decompress";
const SHORT: &str = "compressed file (decmpfs) that did not decompress to its size";
const TABLE: &str = "compressed file (decmpfs) whose table of blocks is damaged or cut";
const CUT: &str =
    "compressed file (decmpfs) whose resource fork does not hold a block of its table";
const BAD_BLOCK: &str =
    "compressed file (decmpfs) with a block that did not decompress to its size";

/// The file `attr` describes. A file whose bytes are in `fork` is read a block
/// at a time, held when it is at most `cap` bytes and else read as it goes. One
/// whose bytes are in the attribute is decoded whole, and reported past `cap`.
#[inline]
pub(crate) fn file<'a, 'b, F: Fork + 'a>(
    v: &'a mut Vol<'b>,
    attr: &[u8],
    fork: Option<F>,
    cap: u64,
) -> Got<'a>
where
    'b: 'a,
{
    file_of(
        v,
        attr,
        fork.map(|f| Box::new(f) as Box<dyn Fork + 'a>),
        cap,
    )
}

/// [`file`], the one compiled copy.
fn file_of<'a, 'b>(
    v: &'a mut Vol<'b>,
    attr: &[u8],
    fork: Option<Box<dyn Fork + 'a>>,
    cap: u64,
) -> Got<'a>
where
    'b: 'a,
{
    let Some(h) = header(attr) else {
        return Got::Why(DAMAGED);
    };
    if !matches!(h.kind, 1 | 3 | 4 | 7 | 8 | 9 | 10 | 11 | 12) {
        return Got::Why(NOT_READ);
    }
    if !in_fork(h.kind) {
        return inline(h.kind, attr.get(HEADER..).unwrap_or_default(), h.size, cap);
    }
    let Some(fork) = fork else {
        return Got::Why(NO_FORK);
    };
    match Blocks::open(v, h.kind, h.size, fork) {
        Some(blocks) => read_file(v, blocks, h.size, cap),
        None => Got::Why(BAD),
    }
}

/// A file whose bytes are in the attribute, as one unit.
fn inline(kind: u32, payload: &[u8], size: u64, cap: u64) -> Got<'static> {
    if size > cap {
        return Got::Big(size);
    }
    let want = crate::bytes::to_usize(size);
    let (data, whole) = match kind {
        1 => (payload.to_vec(), payload.len() == want),
        3 => zlib(payload, want),
        7 => lzvn(payload, want),
        9 => match payload.split_first() {
            Some((0xCC, rest)) => (rest.to_vec(), rest.len() == want),
            _ => (Vec::new(), false),
        },
        _ => lzfse(payload, want),
    };
    match (whole, data.is_empty()) {
        (true, _) => Got::Whole(data),
        (false, true) => Got::Why(BAD),
        (false, false) => Got::Partial(data, SHORT),
    }
}

fn blocks(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64)
}

/// The uncompressed length of block `k`, short only for the last.
fn block_len(size: u64, k: u64) -> usize {
    crate::bytes::to_usize(
        size.saturating_sub(k.saturating_mul(BLOCK as u64))
            .min(BLOCK as u64),
    )
}

/// The blocks of a file in a resource fork, one per step.
struct Blocks<'a> {
    kind: u32,
    size: u64,
    fork: Box<dyn Fork + 'a>,
    /// Where the table's entries are in the fork, and how long each is.
    table: u64,
    entry: u64,
    /// How many blocks the file has, and the next one.
    count: u64,
    k: u64,
    /// A window of the table, where in the fork it starts, and how much of
    /// the table a refill reads.
    window: Vec<u8>,
    window_at: u64,
    reach: usize,
    /// The coded bytes of the block being decoded.
    coded: Vec<u8>,
}

impl<'a> Blocks<'a> {
    /// The blocks of the file of `size` bytes of type `kind` in `fork`, or
    /// `None` when the fork's own header does not say what the file does.
    fn open(v: &mut Vol, kind: u32, size: u64, fork: Box<dyn Fork + 'a>) -> Option<Self> {
        let mut b = Blocks {
            kind,
            size,
            fork,
            table: 0,
            entry: 4,
            count: blocks(size),
            k: 0,
            window: Vec::new(),
            window_at: 0,
            reach: TABLE_WINDOW,
            coded: Vec::new(),
        };
        if kind == 4 {
            // The fork opens with the big-endian offset of its resource data,
            // which opens with a block count and a table of (offset, length)
            // pairs, both little-endian and from the count's place.
            let at = u64::from(be32(b.table_bytes(v, 0, 4)?, 0));
            let counted = at.checked_add(4)?;
            if u64::from(le32(b.table_bytes(v, counted, 4)?, 0)) != b.count {
                return None;
            }
            b.table = counted.checked_add(4)?;
            b.entry = 8;
        }
        Some(b)
    }

    /// `n` bytes of the fork at `off`, through the window.
    fn table_bytes(&mut self, v: &mut Vol, off: u64, n: usize) -> Option<&[u8]> {
        let end = off.checked_add(n as u64)?;
        let held = self.window_at.saturating_add(self.window.len() as u64);
        if off < self.window_at || end > held {
            let room = self.fork.size().checked_sub(off)?;
            if (n as u64) > room {
                return None;
            }
            let want = crate::bytes::to_usize(room.min(self.reach as u64)).max(n);
            self.window.clear();
            if !self.fork.read(v, off, want, &mut self.window) {
                self.window.clear();
                return None;
            }
            self.window_at = off;
        }
        let from = crate::bytes::to_usize(off.saturating_sub(self.window_at));
        self.window.get(from..from.checked_add(n)?)
    }

    /// Where block `k` is in the fork, and how long it is coded.
    fn locate(&mut self, v: &mut Vol) -> Option<(u64, u64)> {
        let at = self.table.checked_add(self.k.checked_mul(self.entry)?)?;
        if self.kind == 4 {
            let e = self.table_bytes(v, at, 8)?;
            let (start, len) = (u64::from(le32(e, 0)), u64::from(le32(e, 4)));
            // The offset is from the count's place, which is 4 bytes back from
            // the table.
            let from = self.table.checked_sub(4)?;
            Some((from.checked_add(start)?, len))
        } else {
            // The block runs to the offset of the next one.
            let e = self.table_bytes(v, at, 8)?;
            let (start, end) = (u64::from(le32(e, 0)), u64::from(le32(e, 4)));
            Some((start, end.checked_sub(start)?))
        }
    }
}

impl Fill for Blocks<'_> {
    fn fill(&mut self, v: &mut Vol, out: &mut Vec<u8>) -> Step {
        if self.k >= self.count {
            return Step::End;
        }
        let Some((start, len)) = self.locate(v) else {
            return Step::Broken(TABLE);
        };
        // A coded block is no longer than a stored one: a marker and 64 KiB.
        if len > (BLOCK as u64).saturating_add(1) {
            return Step::Broken(TABLE);
        }
        self.coded.clear();
        if !self
            .fork
            .read(v, start, crate::bytes::to_usize(len), &mut self.coded)
        {
            return Step::Broken(CUT);
        }
        let want = block_len(self.size, self.k);
        let (data, whole) = match self.kind {
            4 => zlib(&self.coded, want),
            8 => lzvn(&self.coded, want),
            10 => {
                let rest = self.coded.get(1..).unwrap_or_default();
                (rest.to_vec(), rest.len() == want)
            }
            _ => lzfse(&self.coded, want),
        };
        out.extend_from_slice(&data);
        self.k = self.k.saturating_add(1);
        match whole {
            true => Step::More,
            false => Step::Broken(BAD_BLOCK),
        }
    }
}

/// What a decoder made of `want` bytes: what came out, and whether it is
/// exactly that.
type Decoded = (Vec<u8>, bool);

/// zlib, or stored bytes behind a first byte whose low nibble is 0xF, which
/// no zlib stream opens with.
fn zlib(data: &[u8], want: usize) -> Decoded {
    let Some(first) = data.first() else {
        return (Vec::new(), false);
    };
    if first & 0x0f == 0x0f {
        let rest = data.get(1..).unwrap_or_default();
        return (rest.to_vec(), rest.len() == want);
    }
    match crate::inflate::zlib_body(data) {
        Some(r) => {
            let s = crate::salvage(r, want as u64);
            let whole = !s.over_cap && s.data.len() == want;
            (s.data, whole)
        }
        None => (Vec::new(), false),
    }
}

/// LZVN, or stored bytes behind 0x06, which is the end opcode and so opens no
/// coded block.
fn lzvn(data: &[u8], want: usize) -> Decoded {
    match data.split_first() {
        None => (Vec::new(), false),
        Some((0x06, rest)) => (rest.to_vec(), rest.len() == want),
        Some(_) => {
            let s = super::lzfse::decode_lzvn(data, want as u64);
            let whole = !s.over_cap && !s.undecoded && !s.cut_short && s.data.len() == want;
            (s.data, whole)
        }
    }
}

fn lzfse(data: &[u8], want: usize) -> Decoded {
    let s = super::lzfse::decode(data, want as u64);
    let whole = !s.over_cap && !s.undecoded && !s.cut_short && s.data.len() == want;
    (s.data, whole)
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Cursor, Read, Write};
    use std::rc::Rc;

    fn attr(kind: u32, size: usize, payload: &[u8]) -> Vec<u8> {
        attr64(kind, size as u64, payload)
    }

    /// [`attr`] for a size that a 32-bit `usize` does not hold.
    fn attr64(kind: u32, size: u64, payload: &[u8]) -> Vec<u8> {
        let mut a = b"fpmc".to_vec();
        a.extend_from_slice(&kind.to_le_bytes());
        a.extend_from_slice(&size.to_le_bytes());
        a.extend_from_slice(payload);
        a
    }

    fn deflated(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn lzfsed(data: &[u8]) -> Vec<u8> {
        let mut enc = Vec::new();
        lzfse_rust::encode_bytes(data, &mut enc).unwrap();
        enc
    }

    /// `data` as LZVN literals and the end opcode, built without the decoder.
    fn lzvned(data: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        for c in data.chunks(271) {
            match c.len() {
                1..=15 => p.push(0xe0 | c.len() as u8),
                n => p.extend_from_slice(&[0xe0, (n - 16) as u8]),
            }
            p.extend_from_slice(c);
        }
        p.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        p
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| b"the quick brown fox "[i % 20] ^ (i / 997) as u8 & 3)
            .collect()
    }

    /// A resource fork in memory, counting what is read from it.
    struct Mem {
        data: Vec<u8>,
        biggest: Cell<usize>,
        total: Cell<usize>,
    }

    impl Mem {
        fn new(data: Vec<u8>) -> Rc<Mem> {
            Rc::new(Mem {
                data,
                biggest: Cell::new(0),
                total: Cell::new(0),
            })
        }
    }

    impl Fork for Rc<Mem> {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        fn read(&self, _: &mut Vol, off: u64, len: usize, out: &mut Vec<u8>) -> bool {
            self.biggest.set(self.biggest.get().max(len));
            self.total.set(self.total.get() + len);
            match crate::bytes::at(&self.data, off as usize, len) {
                Some(b) => {
                    out.extend_from_slice(b);
                    true
                }
                None => false,
            }
        }
    }

    /// What `file` gave, read to its end.
    #[derive(Debug, PartialEq)]
    enum Out {
        Whole(Vec<u8>),
        /// Held, but not all the file, and why.
        Short(Vec<u8>, &'static str),
        /// Read as it goes: what came, and the error that ended it, if any.
        Stream(Vec<u8>, Option<String>),
        Big(u64),
        Why(&'static str),
    }

    impl Out {
        fn bytes(self) -> Vec<u8> {
            match self {
                Out::Whole(b) => b,
                Out::Why(why) => panic!("{why}"),
                other => panic!("not whole: {:?}", std::mem::discriminant(&other)),
            }
        }

        fn why(self) -> &'static str {
            match self {
                Out::Why(why) => why,
                Out::Big(_) => "over",
                _ => "bytes",
            }
        }
    }

    fn outcome(attr: &[u8], fork: Option<Rc<Mem>>, cap: u64) -> Out {
        let mut c = Cursor::new(Vec::new());
        let mut v = Vol {
            disk: &mut c,
            len: 0,
            max: usize::MAX,
        };
        match file(&mut v, attr, fork, cap) {
            Got::Whole(b) | Got::Sparse(b, _, None) => Out::Whole(b),
            Got::Partial(b, why) | Got::Sparse(b, _, Some(why)) => Out::Short(b, why),
            Got::Big(n) => Out::Big(n),
            Got::Why(why) => Out::Why(why),
            Got::Stream(mut r, _, _) => {
                let mut b = Vec::new();
                let failed = r.read_to_end(&mut b).err().map(|e| e.to_string());
                Out::Stream(b, failed)
            }
            Got::Locked(why) => Out::Why(why),
        }
    }

    /// The coded blocks of `data` in `kind`: zlib, LZVN (stored, or coded
    /// where it is short enough to be), as 8 behind a marker byte, or LZFSE.
    fn encode(kind: u32, data: &[u8]) -> Vec<Vec<u8>> {
        data.chunks(BLOCK)
            .map(|c| match kind {
                4 => deflated(c),
                8 if c.len() < 60_000 => lzvned(c),
                8 => [&[0x06][..], c].concat(),
                10 => [&[0][..], c].concat(),
                _ => lzfsed(c),
            })
            .collect()
    }

    /// The resource fork of a file of `kind` whose coded blocks are `blocks`:
    /// for type 4 a header that says where the table is (here 0x100), the count
    /// and (offset, length) pairs; for the others the offsets of the blocks.
    fn fork_of(kind: u32, blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut fork = Vec::new();
        if kind == 4 {
            fork = vec![0u8; 0x104];
            fork[..4].copy_from_slice(&0x100u32.to_be_bytes());
            fork.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
            let mut at = 4 + 8 * blocks.len();
            for blk in blocks {
                fork.extend_from_slice(&(at as u32).to_le_bytes());
                fork.extend_from_slice(&(blk.len() as u32).to_le_bytes());
                at += blk.len();
            }
        } else {
            let mut at = 4 * (blocks.len() + 1);
            for blk in blocks {
                fork.extend_from_slice(&(at as u32).to_le_bytes());
                at += blk.len();
            }
            fork.extend_from_slice(&(at as u32).to_le_bytes());
        }
        for blk in blocks {
            fork.extend_from_slice(blk);
        }
        fork
    }

    #[test]
    fn the_attribute_types_decode() {
        let data = text(3000);
        for (kind, payload) in [
            (1, data.clone()),
            (3, deflated(&data)),
            (3, [&[0xff][..], &data].concat()),
            (7, lzvned(&data)),
            (7, [&[0x06][..], &data].concat()),
            (9, [&[0xcc][..], &data].concat()),
            (11, lzfsed(&data)),
        ] {
            let a = attr(kind, data.len(), &payload);
            assert_eq!(outcome(&a, None, 1 << 20).bytes(), data, "type {kind}");
        }
    }

    #[test]
    fn the_fork_types_decode_over_several_blocks() {
        // Two blocks, the second short.
        let data = text(70_000);
        for kind in [4, 8, 10, 12] {
            let fork = Mem::new(fork_of(kind, &encode(kind, &data)));
            let a = attr(kind, data.len(), &[]);
            assert_eq!(
                outcome(&a, Some(fork), 1 << 20).bytes(),
                data,
                "type {kind}"
            );
        }
    }

    /// A file of many blocks is read a block at a time: what a step gives, and
    /// what the reader holds between steps, are the size of a block, and the
    /// fork is read in pieces no longer than one, whatever the file's length.
    #[test]
    fn a_long_file_is_read_a_block_at_a_time() {
        let data = text(40 * BLOCK + 123);
        for kind in [4, 8, 10, 12] {
            let blocks = encode(kind, &data);
            let fork = Mem::new(fork_of(kind, &blocks));
            let mut c = Cursor::new(Vec::new());
            let mut v = Vol {
                disk: &mut c,
                len: 0,
                max: usize::MAX,
            };
            let mut b =
                Blocks::open(&mut v, kind, data.len() as u64, Box::new(Rc::clone(&fork))).unwrap();
            // A window of 8 entries, so the table of 41 blocks is read in six.
            b.reach = 64;
            let mut got = Vec::new();
            let mut out = Vec::new();
            let (mut most_out, mut most_window, mut most_coded) = (0, 0, 0);
            loop {
                out.clear();
                let step = b.fill(&mut v, &mut out);
                most_out = most_out.max(out.capacity());
                most_window = most_window.max(b.window.capacity());
                most_coded = most_coded.max(b.coded.capacity());
                got.extend_from_slice(&out);
                match step {
                    Step::More => {}
                    other => {
                        assert!(other == Step::End, "type {kind}: the file ended in damage");
                        break;
                    }
                }
            }
            assert!(got == data, "type {kind}");
            assert!(most_out <= 2 * BLOCK, "type {kind}: a step held {most_out}");
            assert!(
                most_coded <= 2 * (BLOCK + 1),
                "type {kind}: a coded block held {most_coded}"
            );
            assert!(
                most_window <= TABLE_WINDOW,
                "type {kind}: the table window held {most_window}"
            );
            assert!(
                fork.biggest.get() <= BLOCK + 1,
                "type {kind}: the fork was read {} bytes at once",
                fork.biggest.get()
            );
            // Every block is read once, and the table in windows that share an
            // entry at most, besides the first window.
            assert!(
                fork.total.get() < fork.data.len() + TABLE_WINDOW + 16 * 41,
                "type {kind}: {} bytes read of a fork of {}",
                fork.total.get(),
                fork.data.len()
            );
        }
    }

    /// Held when it fits what a member may hold, read as it goes when it does
    /// not, and the same bytes either way.
    #[test]
    fn a_file_over_the_buffer_limit_is_read_as_it_goes() {
        let data = text(10 * BLOCK + 5);
        for kind in [4, 8, 10, 12] {
            let fork = Mem::new(fork_of(kind, &encode(kind, &data)));
            let a = attr(kind, data.len(), &[]);
            let size = data.len() as u64;
            assert!(
                outcome(&a, Some(Rc::clone(&fork)), size).bytes() == data,
                "type {kind}, held"
            );
            let Out::Stream(got, failed) = outcome(&a, Some(Rc::clone(&fork)), size - 1) else {
                panic!("type {kind}: not read as it goes");
            };
            assert!(
                failed.is_none() && got == data,
                "type {kind}, read as it goes"
            );
            assert!(fork.biggest.get() <= BLOCK + 1, "type {kind}");
        }
    }

    /// A fork that gives out part way, or a block that does not decode, ends the
    /// file after the bytes before it, which come out.
    #[test]
    fn a_file_that_breaks_part_way_keeps_what_was_decoded() {
        let data = text(5 * BLOCK);
        for kind in [4, 8, 10, 12] {
            let blocks = encode(kind, &data);
            let a = attr(kind, data.len(), &[]);
            // The fork ends inside the fourth block.
            let mut cut = fork_of(kind, &blocks);
            cut.truncate(cut.len() - blocks[4].len() - blocks[3].len() / 2);
            let held = outcome(&a, Some(Mem::new(cut.clone())), 1 << 30);
            assert!(
                held == Out::Short(data[..3 * BLOCK].to_vec(), CUT),
                "type {kind}, held"
            );
            let streamed = outcome(&a, Some(Mem::new(cut)), 1);
            assert!(
                streamed == Out::Stream(data[..3 * BLOCK].to_vec(), Some(CUT.to_string())),
                "type {kind}, read as it goes"
            );
        }
        // A block that decodes to less than it should is cut there, and what
        // it did decode is kept.
        let mut blocks = encode(12, &data);
        blocks[2] = lzfsed(&data[2 * BLOCK..2 * BLOCK + 1000]);
        let a = attr(12, data.len(), &[]);
        let got = outcome(&a, Some(Mem::new(fork_of(12, &blocks))), 1 << 30);
        assert!(got == Out::Short(data[..2 * BLOCK + 1000].to_vec(), BAD_BLOCK));
        let got = outcome(&a, Some(Mem::new(fork_of(12, &blocks))), 1);
        assert!(
            got == Out::Stream(
                data[..2 * BLOCK + 1000].to_vec(),
                Some(BAD_BLOCK.to_string())
            )
        );
    }

    /// The size is a claim: a file that says it is a terabyte and has two blocks
    /// is read to the end of them, and then it fails.
    #[test]
    fn a_size_the_fork_cannot_back_is_read_to_where_the_fork_ends() {
        let data = text(2 * BLOCK);
        for kind in [8, 10, 12] {
            let fork = Mem::new(fork_of(kind, &encode(kind, &data)));
            let a = attr64(kind, 1 << 40, &[]);
            let Out::Stream(got, failed) = outcome(&a, Some(Rc::clone(&fork)), 1 << 20) else {
                panic!("type {kind}: not read as it goes");
            };
            assert!(
                failed.is_some(),
                "type {kind}: a file that is not all there ended well"
            );
            assert!(got.starts_with(&data), "type {kind}");
            assert!(
                got.len() <= 3 * BLOCK,
                "type {kind}: {} bytes from a fork of {}",
                got.len(),
                fork.data.len()
            );
        }
        // Type 4 says how many blocks it has, which must be what the size makes.
        let fork = Mem::new(fork_of(4, &encode(4, &data)));
        let a = attr64(4, 1 << 40, &[]);
        assert!(
            outcome(&a, Some(fork), 1 << 20)
                .why()
                .contains("did not decompress")
        );
    }

    #[test]
    fn what_cannot_be_decoded_is_reported_not_guessed() {
        let data = text(100);
        let z = deflated(&data);

        // Over the cap, before anything is decoded.
        let a = attr(3, data.len(), &z);
        assert!(matches!(outcome(&a, None, 99), Out::Big(100)));
        assert!(matches!(outcome(&a, None, 100), Out::Whole(_)));

        // A size the stream does not give, either way.
        for size in [99, 101] {
            let a = attr(3, size, &z);
            assert!(
                !matches!(outcome(&a, None, 1 << 20), Out::Whole(_)),
                "size {size}"
            );
        }
        // A cut stream, a wrong marker, a missing fork, a type not read.
        let cut = attr(3, data.len(), &z[..z.len() / 2]);
        assert!(!matches!(outcome(&cut, None, 1 << 20), Out::Whole(_)));
        let marker = attr(9, 3, &[0xcd, 1, 2, 3]);
        assert!(
            outcome(&marker, None, 1 << 20)
                .why()
                .contains("did not decompress")
        );
        let no_fork = attr(8, 10, &[]);
        assert!(
            outcome(&no_fork, None, 1 << 20)
                .why()
                .contains("resource fork is missing")
        );
        for kind in [13, 14, 0x8000_0001, 99] {
            let a = attr(kind, 10, &[]);
            let fork = Mem::new(vec![0u8; 64]);
            assert!(
                outcome(&a, Some(fork), 1 << 20)
                    .why()
                    .contains("type exav does not read"),
                "type {kind}"
            );
        }
        // Not the header.
        assert!(outcome(b"cmpf", None, 1 << 20).why().contains("damaged"));
        let mut a = attr(1, 3, b"abc");
        a[0] = b'x';
        assert!(outcome(&a, None, 1 << 20).why().contains("damaged"));
    }

    /// An attribute that decodes to part of what it says, or to none, is what it
    /// gave, reported, so the bytes are scanned and the file is not clean.
    #[test]
    fn an_attribute_that_decodes_short_gives_what_it_decoded() {
        let data = text(100);
        let z = deflated(&data);
        let a = attr(3, 101, &z);
        assert_eq!(outcome(&a, None, 1 << 20), Out::Short(data.clone(), SHORT));
        let a = attr(1, 101, &data);
        assert_eq!(outcome(&a, None, 1 << 20), Out::Short(data, SHORT));
    }

    /// A table that goes wrong part way: the blocks before the entry that does
    /// are given, and the reason is the table's.
    #[test]
    fn a_table_that_breaks_part_way_gives_the_blocks_before_it() {
        let data = text(5 * BLOCK);
        for kind in [4, 8, 10, 12] {
            let mut fork = fork_of(kind, &encode(kind, &data));
            // Type 4: block 3 is longer than a block can be. The others: the
            // offset of block 3 is before that of block 2, which ends there.
            let (at, kept) = match kind {
                4 => (0x104 + 4 + 8 * 3 + 4, 3),
                _ => (4 * 3, 2),
            };
            let bad: u32 = if kind == 4 { 0x00FF_FFFF } else { 0 };
            fork[at..at + 4].copy_from_slice(&bad.to_le_bytes());
            let a = attr(kind, data.len(), &[]);
            let held = outcome(&a, Some(Mem::new(fork.clone())), 1 << 30);
            assert!(
                held == Out::Short(data[..kept * BLOCK].to_vec(), TABLE),
                "type {kind}, held"
            );
            let streamed = outcome(&a, Some(Mem::new(fork)), 1);
            assert!(
                streamed == Out::Stream(data[..kept * BLOCK].to_vec(), Some(TABLE.to_string())),
                "type {kind}, read as it goes"
            );
        }
    }

    #[test]
    fn a_table_that_points_outside_the_fork_is_damage_not_a_panic() {
        let data = text(70_000);
        for kind in [4, 8, 10, 12] {
            for fork in [
                vec![],
                vec![0xff; 40],
                0x100u32.to_be_bytes().to_vec(),
                [0u8; 300].to_vec(),
                u32::MAX.to_le_bytes().repeat(40),
            ] {
                let a = attr(kind, data.len(), &[]);
                let len = fork.len();
                let got = outcome(&a, Some(Mem::new(fork)), 1 << 20);
                assert!(
                    !matches!(got, Out::Whole(_)),
                    "type {kind}, fork of {len} bytes"
                );
                let got = outcome(&a, Some(Mem::new(vec![0xff; len])), 1);
                assert!(
                    !matches!(got, Out::Whole(_) | Out::Stream(_, None)),
                    "type {kind}, fork of {len} bytes, read as it goes"
                );
            }
        }
    }
}
