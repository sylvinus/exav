//! Random access to the object being scanned.
//!
//! An object is either held in memory, where every consumer reads the slice
//! directly, or read from a seekable source through a [`BlockCache`]: fixed
//! blocks held up to a byte budget, a sequential pass streamed through without
//! evicting the rest, the least recently used evicted otherwise. The cache bounds
//! the memory an object costs, not how far a consumer may look: any offset can
//! be read, and a block evicted is read again from the source when needed.
//!
//! Consumers are written once, generic over [`ByteSource`]. Instantiated for
//! `[u8]` they compile to the slice code they replaced; instantiated for a
//! `dyn ByteSource` they reach the source through the cache.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use crate::stream::Disk;

/// Bytes a [`BlockCache`] reads at a time. The HTTP range reader fetches the
/// same size, so a block is one request.
pub const BLOCK_SIZE: usize = 64 * 1024;

/// Bytes a [`BlockCache`] holds by default, and the default of
/// `--object-cache-bytes` in every exav command and of the scanner's
/// `object_cache_bytes`.
pub const CACHE_BYTES: usize = 32 * 1024 * 1024;

/// Bytes handed to a chunk visitor at a time when the source is not in memory.
/// Small in tests, so a small object crosses many seams.
pub const CHUNK: usize = if cfg!(any(test, feature = "small-chunks")) {
    4096
} else {
    1024 * 1024
};

/// An object's bytes, read at any offset.
pub trait ByteSource {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Up to `len` bytes from `off`, fewer where the object ends. Borrowed
    /// when the object is in memory.
    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]>;

    /// The whole object, when it is held in memory.
    fn as_slice(&self) -> Option<&[u8]> {
        None
    }

    /// Hand `f` consecutive, non-overlapping chunks covering `[from, to)` with
    /// the offset each starts at, until it returns `false`.
    fn chunks(&self, from: usize, to: usize, f: &mut dyn FnMut(usize, &[u8]) -> bool) {
        let to = to.min(self.len());
        let mut at = from;
        while at < to {
            let w = self.window(at, (to - at).min(CHUNK));
            if w.is_empty() || !f(at, &w) {
                return;
            }
            at += w.len();
        }
    }

    /// Start of the first occurrence of `needle` lying wholly inside
    /// `[from, to)`.
    fn find(&self, needle: &[u8], from: usize, to: usize) -> Option<usize> {
        let to = to.min(self.len());
        if needle.is_empty() {
            return (from <= to).then_some(from);
        }
        if from >= to || to - from < needle.len() {
            return None;
        }
        let finder = memchr::memmem::Finder::new(needle);
        let mut at = from;
        // Small first, so a search that ends close by copies little, then
        // doubling. Each window runs `needle.len() - 1` bytes into the next,
        // so an occurrence across the seam is seen whole.
        let mut span = 4096;
        while at + needle.len() <= to {
            let w = self.window(at, (to - at).min(span + needle.len() - 1));
            if w.len() < needle.len() {
                return None;
            }
            if let Some(p) = finder.find(&w) {
                return Some(at + p);
            }
            at += w.len() - (needle.len() - 1);
            span = (span * 2).min(CHUNK);
        }
        None
    }

    /// The whole object, read into memory, when it is at most `limit` bytes.
    fn materialize(&self, limit: usize) -> Option<Cow<'_, [u8]>> {
        if let Some(s) = self.as_slice() {
            return Some(Cow::Borrowed(s));
        }
        if self.len() > limit {
            return None;
        }
        let w = self.window(0, self.len());
        (w.len() == self.len()).then_some(w)
    }

    /// Why a read from the source failed, if one did. Everything read after it
    /// came back short, so a scan that saw one did not see the whole object.
    fn read_error(&self) -> Option<String> {
        None
    }

    /// Identifies this object for as long as it lives, so a decision made
    /// about it cannot be applied to another.
    fn identity(&self) -> (usize, usize);
}

impl ByteSource for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let start = off.min(<[u8]>::len(self));
        let end = start.saturating_add(len).min(<[u8]>::len(self));
        Cow::Borrowed(&self[start..end])
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self)
    }

    fn chunks(&self, from: usize, to: usize, f: &mut dyn FnMut(usize, &[u8]) -> bool) {
        let to = to.min(<[u8]>::len(self));
        if from < to {
            f(from, &self[from..to]);
        }
    }

    fn find(&self, needle: &[u8], from: usize, to: usize) -> Option<usize> {
        let to = to.min(<[u8]>::len(self));
        if from > to {
            return None;
        }
        memchr::memmem::find(&self[from..to], needle).map(|p| from + p)
    }

    fn identity(&self) -> (usize, usize) {
        (self.as_ptr() as usize, <[u8]>::len(self))
    }
}

impl ByteSource for Vec<u8> {
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        ByteSource::window(self.as_slice(), off, len)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self)
    }

    fn chunks(&self, from: usize, to: usize, f: &mut dyn FnMut(usize, &[u8]) -> bool) {
        ByteSource::chunks(self.as_slice(), from, to, f)
    }

    fn find(&self, needle: &[u8], from: usize, to: usize) -> Option<usize> {
        ByteSource::find(self.as_slice(), needle, from, to)
    }

    fn identity(&self) -> (usize, usize) {
        ByteSource::identity(self.as_slice())
    }
}

impl<const N: usize> ByteSource for [u8; N] {
    fn len(&self) -> usize {
        N
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        ByteSource::window(&self[..], off, len)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self)
    }

    fn chunks(&self, from: usize, to: usize, f: &mut dyn FnMut(usize, &[u8]) -> bool) {
        ByteSource::chunks(&self[..], from, to, f)
    }

    fn find(&self, needle: &[u8], from: usize, to: usize) -> Option<usize> {
        ByteSource::find(&self[..], needle, from, to)
    }

    fn identity(&self) -> (usize, usize) {
        ByteSource::identity(&self[..])
    }
}

/// A slice by reference, so bytes held in memory pass as a `&dyn ByteSource`
/// (`&[u8]` itself is unsized and cannot).
impl ByteSource for &[u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        ByteSource::window(*self, off, len)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        Some(self)
    }

    fn chunks(&self, from: usize, to: usize, f: &mut dyn FnMut(usize, &[u8]) -> bool) {
        ByteSource::chunks(*self, from, to, f)
    }

    fn find(&self, needle: &[u8], from: usize, to: usize) -> Option<usize> {
        ByteSource::find(*self, needle, from, to)
    }

    fn identity(&self) -> (usize, usize) {
        ByteSource::identity(*self)
    }
}

/// No slot: the end of the list.
const NIL: usize = usize::MAX;

/// Blocks of a sequential run held at once, once the cache is full: one for
/// the block a pass is in, one for a read that spans into the next.
const RUN_BLOCKS: usize = 2;

/// The two lists of [`Blocks`].
const MAIN: usize = 0;
const RUN: usize = 1;

/// A held block, the list it is in, and its neighbours there.
struct Slot {
    idx: usize,
    data: Box<[u8]>,
    list: usize,
    /// Toward the end inserted or used last.
    hotter: usize,
    /// Toward the end evicted first.
    colder: usize,
}

/// A list of slots: its two ends and its length.
#[derive(Clone, Copy)]
struct Ends {
    hottest: usize,
    coldest: usize,
    len: usize,
}

/// The blocks held: a map from block index to slot, and the slots in two
/// lists, so a hit, an insertion and an eviction are each a constant number
/// of steps.
///
/// A miss on the block after the one read last, once the cache is full, is a
/// sequential pass that will not come back to the block before it has read
/// every other. It goes in a list of its own of [`RUN_BLOCKS`], first in first
/// out, so a pass streams through it and leaves the rest of the cache (what an
/// earlier pass left, the places scattered reads come back to) in place. Every
/// other block is in the main list, the least recently used evicted first.
/// Over passes on an object larger than the cache this keeps what plain LRU
/// evicts just before the next pass needs it.
struct Blocks {
    map: HashMap<usize, usize>,
    slots: Vec<Slot>,
    lists: [Ends; 2],
    /// The block read last, held or not.
    last: Option<usize>,
}

impl Blocks {
    fn new() -> Self {
        let empty = Ends {
            hottest: NIL,
            coldest: NIL,
            len: 0,
        };
        Blocks {
            map: HashMap::new(),
            slots: Vec::new(),
            lists: [empty; 2],
            last: None,
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn unlink(&mut self, s: usize) {
        let (hotter, colder, l) = (
            self.slots[s].hotter,
            self.slots[s].colder,
            self.slots[s].list,
        );
        match hotter {
            NIL => self.lists[l].hottest = colder,
            h => self.slots[h].colder = colder,
        }
        match colder {
            NIL => self.lists[l].coldest = hotter,
            c => self.slots[c].hotter = hotter,
        }
        self.lists[l].len -= 1;
    }

    fn link_hot(&mut self, s: usize, l: usize) {
        let hottest = self.lists[l].hottest;
        let slot = &mut self.slots[s];
        (slot.list, slot.hotter, slot.colder) = (l, NIL, hottest);
        match hottest {
            NIL => self.lists[l].coldest = s,
            h => self.slots[h].hotter = s,
        }
        self.lists[l].hottest = s;
        self.lists[l].len += 1;
    }

    /// Block `idx`'s bytes, if held. A block of the main list becomes its
    /// most recently used.
    fn get(&mut self, idx: usize) -> Option<&[u8]> {
        let s = *self.map.get(&idx)?;
        self.last = Some(idx);
        if self.slots[s].list == MAIN && self.lists[MAIN].hottest != s {
            self.unlink(s);
            self.link_hot(s, MAIN);
        }
        Some(&self.slots[s].data)
    }

    /// Hold block `idx`, just read from the source, in a cache of at most
    /// `max` blocks.
    fn insert(&mut self, idx: usize, data: Box<[u8]>, max: usize) {
        let run = self.last.is_some_and(|l| idx.checked_sub(1) == Some(l));
        self.last = Some(idx);
        let full = self.len() >= max;
        let list = match run && full {
            true => RUN,
            false => MAIN,
        };
        // The list that gives up a block: a run's own once it has its
        // blocks, else the main list while it has any.
        let from = match (
            list,
            self.lists[RUN].len >= RUN_BLOCKS,
            self.lists[MAIN].len,
        ) {
            (RUN, true, _) | (_, _, 0) => RUN,
            _ => MAIN,
        };
        let s = if full && self.lists[from].coldest != NIL {
            let s = self.lists[from].coldest;
            self.unlink(s);
            self.map.remove(&self.slots[s].idx);
            self.slots[s].idx = idx;
            self.slots[s].data = data;
            s
        } else {
            self.slots.push(Slot {
                idx,
                data,
                list,
                hotter: NIL,
                colder: NIL,
            });
            self.slots.len() - 1
        };
        self.map.insert(idx, s);
        self.link_hot(s, list);
    }
}

/// The longest source this build can address: `usize::MAX` bytes.
pub const ADDRESSABLE: u64 = usize::MAX as u64;

/// A seekable source read through fixed blocks, of which at most
/// `capacity` bytes are held.
pub struct BlockCache<R> {
    src: RefCell<R>,
    cache: Cache,
}

/// What a [`BlockCache`] is but for its source, so that the reads of blocks
/// are compiled once for every kind of source.
struct Cache {
    len: usize,
    block: usize,
    blocks: RefCell<Blocks>,
    max_blocks: usize,
    error: RefCell<Option<String>>,
}

impl<R: Read + Seek> BlockCache<R> {
    /// A cache over `src`, whose length is taken now.
    pub fn new(src: R) -> std::io::Result<Self> {
        Self::with_sizes(src, BLOCK_SIZE, CACHE_BYTES)
    }

    /// As [`Self::new`], with the block and cache sizes. A source longer than
    /// this build can address (`usize::MAX` bytes, 4 GiB on a 32-bit target) is
    /// an error, never a source cut short.
    pub fn with_sizes(src: R, block: usize, capacity: usize) -> std::io::Result<Self> {
        Self::with_limit(src, block, capacity, ADDRESSABLE)
    }

    /// [`Self::with_sizes`] for a build that addresses `max_len` bytes.
    fn with_limit(
        mut src: R,
        block: usize,
        capacity: usize,
        max_len: u64,
    ) -> std::io::Result<Self> {
        let len = src.seek(SeekFrom::End(0))?;
        let too_long = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("the source is {len} bytes, past the {max_len} this build can address"),
            )
        };
        if len > max_len {
            return Err(too_long());
        }
        let len = usize::try_from(len).map_err(|_| too_long())?;
        let block = block.max(1);
        Ok(BlockCache {
            src: RefCell::new(src),
            cache: Cache {
                len,
                block,
                blocks: RefCell::new(Blocks::new()),
                max_blocks: (capacity / block).max(2),
                error: RefCell::new(None),
            },
        })
    }
}

impl Cache {
    /// Copy block `idx`'s bytes from `skip` into `out`, up to `want` bytes.
    fn copy_block(
        &self,
        src: &mut dyn Disk,
        idx: usize,
        skip: usize,
        want: usize,
        out: &mut Vec<u8>,
    ) -> bool {
        let mut blocks = self.blocks.borrow_mut();
        if let Some(data) = blocks.get(idx) {
            let end = (skip + want).min(data.len());
            if skip < end {
                out.extend_from_slice(&data[skip..end]);
            }
            return end == skip + want;
        }
        if self.error.borrow().is_some() {
            return false;
        }
        let start = idx * self.block;
        let size = self.block.min(self.len.saturating_sub(start));
        let mut data = vec![0u8; size];
        let got = match src.seek(SeekFrom::Start(start as u64)) {
            Ok(_) => read_full(src, &mut data),
            Err(e) => Err(e),
        };
        match got {
            Ok(n) if n == size => {}
            Ok(n) => {
                *self.error.borrow_mut() = Some(format!(
                    "the source ended at {} of its {} bytes",
                    start + n,
                    self.len
                ));
                data.truncate(n);
            }
            Err(e) => {
                *self.error.borrow_mut() = Some(format!("read at {start} failed: {e}"));
                return false;
            }
        }
        let end = (skip + want).min(data.len());
        if skip < end {
            out.extend_from_slice(&data[skip..end]);
        }
        let whole = end == skip + want;
        blocks.insert(idx, data.into_boxed_slice(), self.max_blocks);
        whole
    }
}

/// Read until `buf` is full or the source ends.
fn read_full(src: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match src.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

impl Cache {
    fn window(&self, src: &mut dyn Disk, off: usize, len: usize) -> Cow<'static, [u8]> {
        let end = off.saturating_add(len).min(self.len);
        if off >= end {
            return Cow::Owned(Vec::new());
        }
        let mut out = Vec::with_capacity(end - off);
        let mut at = off;
        while at < end {
            let idx = at / self.block;
            let skip = at - idx * self.block;
            let want = (self.block - skip).min(end - at);
            if !self.copy_block(src, idx, skip, want, &mut out) {
                break;
            }
            at += want;
        }
        Cow::Owned(out)
    }
}

impl<R: Read + Seek> ByteSource for BlockCache<R> {
    fn len(&self) -> usize {
        self.cache.len
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        self.cache.window(&mut *self.src.borrow_mut(), off, len)
    }

    fn read_error(&self) -> Option<String> {
        self.cache.error.borrow().clone()
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.cache.len)
    }
}

/// Up to this size, a read into memory doubles its buffer; past it, it adds a
/// quarter.
const HOLD_STEP: usize = 64 * 1024;

/// Append to `buf` what `r` gives, up to `max` bytes. The bytes read before an
/// error are kept.
///
/// The memory is asked for as the data arrives, from 64 bytes, doubled up to
/// 64 KiB, then a quarter more each time, never past `max`.
/// `read_to_end` doubles all the way: a buffer that fills to `max` has asked
/// for twice that, and where the allocator copies on growth the last step
/// holds both copies at once.
pub fn read_capped(r: &mut dyn Read, buf: &mut Vec<u8>, max: u64) -> std::io::Result<usize> {
    let start = buf.len();
    let end = start.saturating_add(usize::try_from(max).unwrap_or(usize::MAX));
    while buf.len() < end {
        if buf.len() == buf.capacity() {
            let step = match buf.len() {
                n if n < HOLD_STEP => n.max(64),
                n => n / 4,
            };
            let step = step.min(end - buf.len());
            buf.try_reserve_exact(step)
                .map_err(|_| std::io::Error::other("not enough memory to hold the object"))?;
        }
        let before = buf.len();
        let room = buf.capacity().min(end) - before;
        (&mut *r).take(room as u64).read_to_end(buf)?;
        if buf.len() - before < room {
            break;
        }
    }
    Ok(buf.len() - start)
}

/// A reader as the source of a walk: read into memory when it is at most
/// `hold` bytes long, else read where it lies through a block cache of
/// `cache` (block size, capacity in bytes). `len` is its length; a reader that
/// is longer than that is held up to `hold` bytes and one byte more.
pub fn open_source<R: Read + Seek + 'static>(
    mut reader: R,
    len: u64,
    hold: u64,
    cache: (usize, usize),
) -> std::io::Result<Box<dyn ByteSource>> {
    if len <= hold {
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        (&mut reader)
            .take(hold.saturating_add(1))
            .read_to_end(&mut data)?;
        return Ok(Box::new(data));
    }
    Ok(Box::new(BlockCache::with_sizes(reader, cache.0, cache.1)?))
}

/// `[base, base + len)` of another source, as an object of its own: a region
/// carved out of its carrier.
pub struct Sub<'a> {
    inner: &'a dyn ByteSource,
    base: usize,
    len: usize,
}

impl<'a> Sub<'a> {
    pub fn new(inner: &'a dyn ByteSource, base: usize, len: usize) -> Self {
        let base = base.min(inner.len());
        Sub {
            inner,
            base,
            len: len.min(inner.len() - base),
        }
    }
}

impl ByteSource for Sub<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let off = off.min(self.len);
        let len = len.min(self.len - off);
        self.inner.window(self.base + off, len)
    }

    fn as_slice(&self) -> Option<&[u8]> {
        self.inner
            .as_slice()
            .map(|s| &s[self.base..self.base + self.len])
    }

    fn find(&self, needle: &[u8], from: usize, to: usize) -> Option<usize> {
        let to = to.min(self.len);
        if from > to {
            return None;
        }
        self.inner
            .find(needle, self.base + from, self.base + to)
            .map(|p| p - self.base)
    }

    fn read_error(&self) -> Option<String> {
        self.inner.read_error()
    }

    fn identity(&self) -> (usize, usize) {
        let (id, _) = self.inner.identity();
        (id.wrapping_add(self.base), self.len)
    }
}

/// Another source with ASCII letters lowercased: the haystack the
/// case-insensitive matchers search.
pub struct Lower<'a, B: ?Sized>(pub &'a B);

impl<B: ByteSource + ?Sized> ByteSource for Lower<'_, B> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let mut w = self.0.window(off, len).into_owned();
        w.make_ascii_lowercase();
        Cow::Owned(w)
    }

    fn identity(&self) -> (usize, usize) {
        self.0.identity()
    }
}

/// A `Read + Seek` cursor over a source, for the extractors that take one.
#[derive(Clone)]
pub struct Reader<'a> {
    src: &'a dyn ByteSource,
    pos: u64,
    /// Where in `src` the reader's offset 0 is, and how many bytes it covers.
    base: u64,
    len: u64,
}

impl<'a> Reader<'a> {
    pub fn new(src: &'a dyn ByteSource) -> Self {
        Self::range(src, 0, src.len())
    }

    /// A reader over `[from, to)` of `src` only, its offsets counted from `from`.
    pub fn range(src: &'a dyn ByteSource, from: usize, to: usize) -> Self {
        let to = to.min(src.len());
        let from = from.min(to);
        Reader {
            src,
            pos: 0,
            base: from as u64,
            len: (to - from) as u64,
        }
    }
}

impl Read for Reader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.len;
        if self.pos >= len {
            return Ok(0);
        }
        let want = buf.len().min((len - self.pos) as usize).min(CHUNK);
        let w = self.src.window((self.base + self.pos) as usize, want);
        if w.is_empty() {
            return Err(std::io::Error::other(
                self.src
                    .read_error()
                    .unwrap_or_else(|| "the source ended early".to_string()),
            ));
        }
        buf[..w.len()].copy_from_slice(&w);
        self.pos += w.len() as u64;
        Ok(w.len())
    }
}

impl Seek for Reader<'_> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let len = self.len as i128;
        let pos = match to {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => len + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before the start",
            ));
        }
        // A position past `u64` is not one: wrapped, it would land at the start.
        // A position past `u64` is not one: wrapped, it would land at the start.
        self.pos = u64::try_from(pos).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek past the largest offset",
            )
        })?;
        Ok(self.pos)
    }
}

/// An object's bytes by index, for scans written as index loops: a slice
/// ([`Indexed`]), or a source read through a sliding window ([`Stepper`]).
pub trait Bytes {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The byte at `i`, which is below `len()`. 0 where the source could not
    /// be read.
    fn at(&mut self, i: usize) -> u8;

    /// `[from, to)`, clamped to the object.
    fn range(&mut self, from: usize, to: usize) -> Cow<'_, [u8]>;
}

pub struct Indexed<'a>(pub &'a [u8]);

impl Bytes for Indexed<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn at(&mut self, i: usize) -> u8 {
        self.0[i]
    }

    fn range(&mut self, from: usize, to: usize) -> Cow<'_, [u8]> {
        let to = to.min(self.0.len());
        Cow::Borrowed(&self.0[from.min(to)..to])
    }
}

/// A source read a chunk at a time, keeping [`Stepper::BEHIND`] bytes before
/// the chunk's start so a short look back needs no read.
pub struct Stepper<'a> {
    src: &'a dyn ByteSource,
    buf: Cow<'a, [u8]>,
    base: usize,
}

impl<'a> Stepper<'a> {
    pub const BEHIND: usize = 128;

    pub fn new(src: &'a dyn ByteSource) -> Self {
        Stepper {
            src,
            buf: Cow::Borrowed(&[]),
            base: 0,
        }
    }
}

impl Bytes for Stepper<'_> {
    fn len(&self) -> usize {
        self.src.len()
    }

    #[inline]
    fn at(&mut self, i: usize) -> u8 {
        if i < self.base || i - self.base >= self.buf.len() {
            self.base = i.saturating_sub(Self::BEHIND);
            self.buf = self.src.window(self.base, CHUNK + Self::BEHIND);
        }
        self.buf.get(i - self.base).copied().unwrap_or(0)
    }

    fn range(&mut self, from: usize, to: usize) -> Cow<'_, [u8]> {
        let to = to.min(self.src.len());
        let from = from.min(to);
        if from >= self.base && to - self.base <= self.buf.len() {
            return Cow::Borrowed(&self.buf[from - self.base..to - self.base]);
        }
        self.src.window(from, to - from)
    }
}

/// Every byte in `[from, to)`, in order, read a chunk at a time.
pub fn bytes<'a, B: ByteSource + ?Sized>(
    src: &'a B,
    from: usize,
    to: usize,
) -> impl Iterator<Item = u8> + 'a {
    let to = to.min(src.len());
    let mut at = from;
    let mut buf: Cow<'a, [u8]> = Cow::Owned(Vec::new());
    let mut i = 0;
    std::iter::from_fn(move || {
        if i == buf.len() {
            if at >= to {
                return None;
            }
            buf = src.window(at, (to - at).min(CHUNK));
            if buf.is_empty() {
                return None;
            }
            at += buf.len();
            i = 0;
        }
        i += 1;
        Some(buf[i - 1])
    })
}

/// A source that claims `claimed` bytes and delivers only `data`, for tests of
/// what a failed read does.
#[cfg(test)]
pub(crate) fn short_source(data: &[u8], claimed: u64) -> BlockCache<impl Read + Seek + use<>> {
    struct Short(std::io::Cursor<Vec<u8>>, u64);
    impl Read for Short {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(b)
        }
    }
    impl Seek for Short {
        fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
            match p {
                SeekFrom::End(_) => Ok(self.1),
                p => self.0.seek(p),
            }
        }
    }
    BlockCache::with_sizes(Short(std::io::Cursor::new(data.to_vec()), claimed), 64, 256).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// A source longer than the build addresses is an error. It used to be
    /// cut at the largest length, with the bytes past it never read and
    /// nothing said.
    #[test]
    fn a_source_longer_than_the_build_addresses_is_an_error_not_a_cut() {
        let d = data(5000);
        let len = |max| BlockCache::with_limit(Cursor::new(d.clone()), 64, 256, max);
        assert_eq!(len(5000).unwrap().len(), 5000);
        assert_eq!(len(u64::MAX).unwrap().len(), 5000);
        let e = len(4999).err().expect("past the limit");
        assert!(e.to_string().contains("5000"), "{e}");
        assert!(e.to_string().contains("4999"), "{e}");
        assert!(len(0).is_err());
    }

    /// The same on a 32-bit target, where the limit is `usize::MAX`: a source
    /// of 5 GiB, which is not held, only measured.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn a_source_past_4_gib_is_an_error_on_a_32_bit_target() {
        struct Huge;
        impl Read for Huge {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf.fill(0);
                Ok(buf.len())
            }
        }
        impl Seek for Huge {
            fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
                match to {
                    SeekFrom::End(0) => Ok(5 << 30),
                    other => panic!("{other:?}"),
                }
            }
        }
        assert!(BlockCache::new(Huge).is_err());
        assert!(BlockCache::with_sizes(Huge, 4096, 1 << 20).is_err());
    }

    /// A seek past the largest offset is an error; it used to wrap to a small
    /// one, which passes any check made against the end of the object.
    #[test]
    fn a_seek_past_u64_is_an_error_not_a_wrap() {
        let d = data(100);
        let slice = d.as_slice();
        let mut r = Reader::new(&slice);
        assert_eq!(r.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        assert!(r.seek(SeekFrom::Current(2)).is_err());
        assert_eq!(r.seek(SeekFrom::Start(5)).unwrap(), 5);
    }

    #[test]
    fn a_cached_source_reads_what_the_slice_holds() {
        let d = data(10_000);
        // Blocks small enough that reads cross them, a cache small enough to
        // evict.
        let c = BlockCache::with_sizes(Cursor::new(d.clone()), 64, 256).unwrap();
        assert_eq!(c.len(), d.len());
        for (off, len) in [
            (0, 10),
            (60, 10),
            (63, 2),
            (500, 1000),
            (9990, 50),
            (10_000, 5),
            (20_000, 5),
        ] {
            assert_eq!(c.window(off, len), d.window(off, len), "({off}, {len})");
        }
        assert!(c.cache.blocks.borrow().len() <= 4);
        assert_eq!(c.read_error(), None);
    }

    /// A cursor that counts the reads made of it.
    struct Counted(Cursor<Vec<u8>>, std::rc::Rc<std::cell::Cell<usize>>);

    impl Read for Counted {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.1.set(self.1.get() + 1);
            self.0.read(b)
        }
    }

    impl Seek for Counted {
        fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(p)
        }
    }

    /// A cache of 8 blocks of 64 bytes over 64 blocks, and its read counter.
    fn counted() -> (BlockCache<Counted>, std::rc::Rc<std::cell::Cell<usize>>) {
        let reads = std::rc::Rc::default();
        let src = Counted(Cursor::new(data(64 * 64)), std::rc::Rc::clone(&reads));
        (BlockCache::with_sizes(src, 64, 8 * 64).unwrap(), reads)
    }

    /// The blocks read from the source by `f`.
    fn reads_by(
        c: &BlockCache<Counted>,
        reads: &std::cell::Cell<usize>,
        f: impl Fn(&BlockCache<Counted>),
    ) -> usize {
        let before = reads.get();
        f(c);
        reads.get() - before
    }

    fn pass(c: &BlockCache<Counted>) {
        for b in 0..64 {
            c.window(b * 64, 64);
        }
    }

    /// A pass over an object larger than the cache streams through it: the
    /// blocks the first pass left are there for the next. Least recently used
    /// alone evicts each just before the next pass needs it, and every pass
    /// reads every block.
    #[test]
    fn passes_keep_what_the_first_pass_left() {
        let (c, reads) = counted();
        assert_eq!(reads_by(&c, &reads, pass), 64);
        for _ in 0..3 {
            let n = reads_by(&c, &reads, pass);
            // Six blocks kept, the two others streamed through.
            assert!(n <= 59, "a later pass read {n} of the 64 blocks");
        }
        assert!(c.cache.blocks.borrow().len() <= 8);
    }

    /// Blocks a scattered read comes back to survive a pass over the object.
    #[test]
    fn a_pass_does_not_evict_the_scattered_reads() {
        let (c, reads) = counted();
        pass(&c);
        let scattered = |c: &BlockCache<Counted>| {
            for b in [40, 50, 60] {
                c.window(b * 64 + 3, 10);
            }
        };
        scattered(&c);
        pass(&c);
        assert_eq!(reads_by(&c, &reads, scattered), 0);
    }

    /// Two passes at once, through different parts of the object and in
    /// windows that span two blocks, read each block once.
    #[test]
    fn two_passes_at_once_read_each_block_once() {
        let (c, reads) = counted();
        pass(&c);
        let n = reads_by(&c, &reads, |c| {
            for b in 0..31 {
                c.window(b * 64 + 40, 64);
                c.window((b + 32) * 64 + 40, 64);
            }
        });
        // The blocks of both halves, less what the first pass left.
        assert!(n <= 64, "{n} reads");
    }

    /// Reads at any offset, through a cache of a few small blocks, return what
    /// the slice holds, and the cache never holds more than its blocks.
    #[test]
    fn random_reads_agree_with_the_slice() {
        let d = data(5000);
        let c = BlockCache::with_sizes(Cursor::new(d.clone()), 16, 5 * 16).unwrap();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for i in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Runs of consecutive blocks among the scattered reads.
            let off = match i % 3 {
                0 => (state % 5100) as usize,
                _ => (i * 16) % 5000,
            };
            let len = (state >> 20) as usize % 70;
            assert_eq!(c.window(off, len), d.window(off, len), "({off}, {len})");
            let b = c.cache.blocks.borrow();
            assert!(b.len() <= 5 && b.slots.len() <= 5);
        }
    }

    #[test]
    fn find_agrees_with_the_slice_across_seams() {
        let mut d = vec![b'x'; 3 * CHUNK];
        for at in [5, CHUNK - 2, 2 * CHUNK - 1, 3 * CHUNK - 4] {
            d[at..at + 4].copy_from_slice(b"abcd");
        }
        let c = BlockCache::with_sizes(Cursor::new(d.clone()), 4096, 64 * 1024).unwrap();
        let mut from = 0;
        while let Some(p) = d.find(b"abcd", from, d.len()) {
            assert_eq!(c.find(b"abcd", from, d.len()), Some(p));
            from = p + 1;
        }
        assert_eq!(c.find(b"abcd", from, d.len()), None);
        // The range end is honoured.
        assert_eq!(c.find(b"abcd", 0, 8), None);
        assert_eq!(c.find(b"abcd", 0, 9), Some(5));
    }

    #[test]
    fn a_short_source_is_reported() {
        let c = short_source(&[1; 100], 1000);
        assert_eq!(c.window(0, 1000).len(), 100);
        assert!(c.read_error().is_some());
    }

    #[test]
    fn views_and_readers_agree_with_the_slice() {
        let d = data(5000);
        let c = BlockCache::with_sizes(Cursor::new(d.clone()), 64, 256).unwrap();
        let s = Sub::new(&c, 1000, 2000);
        assert_eq!(s.window(10, 100), d.window(1010, 100));
        assert_eq!(
            s.find(&d[1500..1504], 0, 2000),
            d.find(&d[1500..1504], 1000, 3000).map(|p| p - 1000)
        );
        let mut all = Vec::new();
        Reader::new(&c).read_to_end(&mut all).unwrap();
        assert_eq!(all, d);
        assert_eq!(bytes(&c, 100, 4000).collect::<Vec<_>>(), d[100..4000]);
        let l = Lower(&c);
        assert_eq!(l.window(0, 5000).into_owned(), d.to_ascii_lowercase());
        assert_eq!(c.materialize(4999), None);
        assert_eq!(c.materialize(5000).as_deref(), Some(&d[..]));
    }

    /// A read into memory asks for about what it reads: a few bytes for a
    /// small member, the limit and no more for one that reaches it.
    #[test]
    fn a_capped_read_asks_for_about_what_it_reads() {
        let mut small = Vec::new();
        read_capped(&mut &b"abcd"[..], &mut small, 256 << 20).unwrap();
        assert_eq!(small, b"abcd");
        assert!(small.capacity() <= 64, "{}", small.capacity());
        let d = vec![7u8; (1 << 20) + 1];
        let mut big = Vec::new();
        read_capped(&mut &d[..], &mut big, 1 << 20).unwrap();
        assert_eq!(big.len(), 1 << 20);
        assert_eq!(big.capacity(), 1 << 20);
    }

    #[test]
    fn a_reader_is_held_up_to_the_limit_and_read_in_place_past_it() {
        let d = data(1000);
        // At the limit: held, and its bytes are in memory.
        let held = open_source(Cursor::new(d.clone()), 1000, 1000, (64, 256)).unwrap();
        assert_eq!(held.as_slice(), Some(&d[..]));
        // One byte past it: read where it lies, whole through the cache.
        let cached = open_source(Cursor::new(d.clone()), 1000, 999, (64, 256)).unwrap();
        assert_eq!(cached.as_slice(), None);
        assert_eq!(cached.len(), 1000);
        assert_eq!(cached.window(100, 50), d.window(100, 50));
        // An empty one is held.
        let empty = open_source(Cursor::new(Vec::new()), 0, 0, (64, 256)).unwrap();
        assert_eq!(empty.as_slice(), Some(&[][..]));
        // A reader longer than it said is held up to the limit and a byte more.
        let long = open_source(Cursor::new(d.clone()), 10, 20, (64, 256)).unwrap();
        assert_eq!(long.as_slice(), Some(&d[..21]));
        // A cache that cannot be made (the source cannot be measured) is an error.
        struct Unseekable;
        impl Read for Unseekable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl Seek for Unseekable {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Err(std::io::Error::other("no"))
            }
        }
        assert!(open_source(Unseekable, 100, 10, (64, 256)).is_err());
    }
}
