//! Random access to the object being scanned.
//!
//! An object is either held in memory, where every consumer reads the slice
//! directly, or read from a seekable source through a [`BlockCache`]: fixed
//! blocks, the least recently used evicted past a byte budget. The cache bounds
//! the memory an object costs, not how far a consumer may look: any offset can
//! be read, and a block evicted is read again from the source when needed.
//!
//! Consumers are written once, generic over [`ByteSource`]. Instantiated for
//! `[u8]` they compile to the slice code they replaced; instantiated for a
//! `dyn ByteSource` they reach the source through the cache.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

/// Bytes a [`BlockCache`] reads at a time. The HTTP range reader fetches the
/// same size, so a block is one request.
pub const BLOCK_SIZE: usize = 64 * 1024;

/// Bytes a [`BlockCache`] holds by default.
pub const CACHE_BYTES: usize = 8 * 1024 * 1024;

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

/// Blocks held, by index, with the tick each was last used at.
type Blocks = HashMap<usize, (Box<[u8]>, u64)>;

/// A seekable source read through fixed blocks, of which at most
/// `capacity` bytes are held.
pub struct BlockCache<R> {
    src: RefCell<R>,
    len: usize,
    block: usize,
    blocks: RefCell<Blocks>,
    max_blocks: usize,
    tick: Cell<u64>,
    error: RefCell<Option<String>>,
}

impl<R: Read + Seek> BlockCache<R> {
    /// A cache over `src`, whose length is taken now.
    pub fn new(src: R) -> std::io::Result<Self> {
        Self::with_sizes(src, BLOCK_SIZE, CACHE_BYTES)
    }

    pub fn with_sizes(mut src: R, block: usize, capacity: usize) -> std::io::Result<Self> {
        let len = src.seek(SeekFrom::End(0))?;
        let block = block.max(1);
        Ok(BlockCache {
            src: RefCell::new(src),
            len: usize::try_from(len).unwrap_or(usize::MAX),
            block,
            blocks: RefCell::new(HashMap::new()),
            max_blocks: (capacity / block).max(2),
            tick: Cell::new(0),
            error: RefCell::new(None),
        })
    }

    /// Copy block `idx`'s bytes from `skip` into `out`, up to `want` bytes.
    fn copy_block(&self, idx: usize, skip: usize, want: usize, out: &mut Vec<u8>) -> bool {
        let tick = self.tick.get() + 1;
        self.tick.set(tick);
        let mut blocks = self.blocks.borrow_mut();
        if let Some((data, used)) = blocks.get_mut(&idx) {
            *used = tick;
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
        let got = {
            let mut src = self.src.borrow_mut();
            match src.seek(SeekFrom::Start(start as u64)) {
                Ok(_) => read_full(&mut *src, &mut data),
                Err(e) => Err(e),
            }
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
        if blocks.len() >= self.max_blocks {
            if let Some(&old) = blocks
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k)
            {
                blocks.remove(&old);
            }
        }
        blocks.insert(idx, (data.into_boxed_slice(), tick));
        whole
    }
}

/// Read until `buf` is full or the source ends.
fn read_full<R: Read + ?Sized>(src: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
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

impl<R: Read + Seek> ByteSource for BlockCache<R> {
    fn len(&self) -> usize {
        self.len
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
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
            if !self.copy_block(idx, skip, want, &mut out) {
                break;
            }
            at += want;
        }
        Cow::Owned(out)
    }

    fn read_error(&self) -> Option<String> {
        self.error.borrow().clone()
    }

    fn identity(&self) -> (usize, usize) {
        (self as *const Self as usize, self.len)
    }
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
pub(crate) fn short_source(data: &[u8], claimed: u64) -> BlockCache<impl Read + Seek> {
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
        assert!(c.blocks.borrow().len() <= 4);
        assert_eq!(c.read_error(), None);
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
}
