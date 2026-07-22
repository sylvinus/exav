//! The byte sources `exav_unpack::Archive` reads through.
//!
//! `Archive` is `Read + Seek`, which is to say synchronous, and that is not an
//! obstacle to be worked around — it is the reason this crate can share ONE set
//! of archive readers with the rest of exav instead of carrying a second that
//! drifts. What it needs is a synchronous way to read a `Blob`, and browsers
//! have exactly one: [`web_sys::FileReaderSync`], which exists only inside a
//! Worker. So the `File` path runs in a Worker, and `js/index.js` turns that
//! into the async API a caller on the main thread sees.
//!
//! Bytes already in memory need none of this: a `Cursor` is `Read + Seek`
//! already, so that path stays on the main thread and costs no Worker at all.

use std::io::{self, Read, Seek, SeekFrom};

use wasm_bindgen::prelude::*;

/// How much one fetch pulls.
///
/// The archive readers ask for small pieces — a ZIP central-directory walk
/// reads two-byte and four-byte fields. Serving each of those with its own trip
/// out to JS would make opening an archive thousands of round trips, so reads
/// are served from a window this size and only a miss goes out.
const WINDOW: u64 = 256 * 1024;

/// Somewhere bytes can be fetched from by absolute offset.
pub(crate) trait Fetch {
    fn len(&self) -> u64;
    fn fetch(&self, at: u64, len: u64) -> io::Result<Vec<u8>>;
}

/// A `Read + Seek` view of anything that can be fetched from by offset.
pub(crate) struct Windowed<F: Fetch> {
    src: F,
    pos: u64,
    window: Vec<u8>,
    window_at: u64,
}

impl<F: Fetch> Windowed<F> {
    fn new(src: F) -> Self {
        Windowed {
            src,
            pos: 0,
            window: Vec::new(),
            window_at: 0,
        }
    }
}

impl<F: Fetch> Read for Windowed<F> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = self.src.len();
        if out.is_empty() || self.pos >= len {
            return Ok(0);
        }
        let covered = self.pos >= self.window_at
            && self.pos < self.window_at.saturating_add(self.window.len() as u64);
        if !covered {
            let end = self.pos.saturating_add(WINDOW).min(len);
            self.window = self.src.fetch(self.pos, end - self.pos)?;
            self.window_at = self.pos;
        }
        let from = (self.pos - self.window_at) as usize;
        let Some(avail) = self.window.get(from..).filter(|a| !a.is_empty()) else {
            // A source that returns nothing where it said there were bytes is
            // at its end, whatever its declared length claimed.
            return Ok(0);
        };
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<F: Fetch> Seek for Windowed<F> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let at = match to {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => self.src.len() as i64 + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if at < 0 {
            return Err(io::Error::other("seek before the start of the archive"));
        }
        // Seeking PAST the end is legal and reads nothing; the next `read`
        // returns zero bytes. Refusing here would reject a reader that seeks to
        // a computed offset before checking it.
        self.pos = at as u64;
        Ok(self.pos)
    }
}

/// A `Blob`, read through `FileReaderSync`.
pub(crate) struct BlobFetch {
    blob: web_sys::Blob,
    reader: web_sys::FileReaderSync,
    len: u64,
}

impl Fetch for BlobFetch {
    fn len(&self) -> u64 {
        self.len
    }

    fn fetch(&self, at: u64, len: u64) -> io::Result<Vec<u8>> {
        // `slice_with_f64_and_f64` reads a NEGATIVE argument as an offset from
        // the end of the blob, so both bounds are kept non-negative and inside
        // the length rather than passed through arithmetic that could go below
        // zero. Sizes here are far under 2^53, where `f64` is exact.
        let end = at.saturating_add(len).min(self.len);
        if at >= end {
            return Ok(Vec::new());
        }
        let slice = self
            .blob
            .slice_with_f64_and_f64(at as f64, end as f64)
            .map_err(|_| io::Error::other("Blob::slice failed"))?;
        let buf = self
            .reader
            .read_as_array_buffer(&slice)
            .map_err(|_| io::Error::other("FileReaderSync::readAsArrayBuffer failed"))?;
        Ok(js_sys::Uint8Array::new(&buf).to_vec())
    }
}

/// A caller-supplied `{ read(offset, length): Uint8Array, size: number }`.
///
/// `read` is SYNCHRONOUS. An async one cannot be called from here at all — the
/// archive readers are `Read + Seek`, and there is no way to await inside a
/// `read` that returns bytes. Supplying a source is still the escape hatch it
/// always was; what it hands back is bytes rather than a promise of them.
pub(crate) struct JsFetch {
    read: js_sys::Function,
    this: JsValue,
    len: u64,
}

impl Fetch for JsFetch {
    fn len(&self) -> u64 {
        self.len
    }

    fn fetch(&self, at: u64, len: u64) -> io::Result<Vec<u8>> {
        let got = self
            .read
            .call2(&self.this, &JsValue::from_f64(at as f64), &JsValue::from_f64(len as f64))
            .map_err(|e| io::Error::other(format!("reader.read threw: {e:?}")))?;
        let bytes = got.dyn_ref::<js_sys::Uint8Array>().ok_or_else(|| {
            io::Error::other("reader.read must return a Uint8Array synchronously")
        })?;
        Ok(bytes.to_vec())
    }
}

/// Whichever source this archive was opened from.
///
/// One concrete type rather than a generic parameter: `exav_unpack::Archive<R>`
/// would otherwise be a different type per source, and the exported `Archive`
/// can only be one of them.
pub(crate) enum Src {
    Memory(io::Cursor<Vec<u8>>),
    Blob(Box<Windowed<BlobFetch>>),
    Js(Box<Windowed<JsFetch>>),
}

impl Src {
    /// Read a `Blob` synchronously. Fails outside a Worker, where
    /// `FileReaderSync` does not exist — the whole constraint this design is
    /// built around, so it is reported as itself rather than as a read error
    /// somewhere later.
    pub(crate) fn from_blob(blob: web_sys::Blob) -> Result<Self, JsValue> {
        let reader = web_sys::FileReaderSync::new().map_err(|_| {
            JsValue::from_str(
                "FileReaderSync is unavailable: reading a File synchronously \
                 requires a Worker",
            )
        })?;
        let len = blob.size() as u64;
        Ok(Src::Blob(Box::new(Windowed::new(BlobFetch {
            blob,
            reader,
            len,
        }))))
    }

    /// Read through a caller-supplied `{ read, size }` object.
    pub(crate) fn from_js_reader(obj: &js_sys::Object) -> Result<Self, JsValue> {
        let read = js_sys::Reflect::get(obj, &"read".into())?;
        let read = read
            .dyn_into::<js_sys::Function>()
            .map_err(|_| JsValue::from_str("reader needs a `read(offset, length)` function"))?;
        let len = js_sys::Reflect::get(obj, &"size".into())?
            .as_f64()
            .filter(|n| *n >= 0.0 && n.is_finite())
            .ok_or_else(|| JsValue::from_str("reader needs a numeric `size`"))?
            as u64;
        Ok(Src::Js(Box::new(Windowed::new(JsFetch {
            read,
            this: obj.into(),
            len,
        }))))
    }
}

impl Read for Src {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Src::Memory(c) => c.read(out),
            Src::Blob(b) => b.read(out),
            Src::Js(j) => j.read(out),
        }
    }
}

impl Seek for Src {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        match self {
            Src::Memory(c) => c.seek(to),
            Src::Blob(b) => b.seek(to),
            Src::Js(j) => j.seek(to),
        }
    }
}
