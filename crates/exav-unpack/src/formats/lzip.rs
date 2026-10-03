//! lzip: one member, every lzip member of the file decoded in turn as it is
//! read.
use std::io::{self, Read, Seek};

use crate::source::{ByteSource, Reader};
use crate::stream::{stream_single, Visit};
use crate::{Budget, LimitHit};

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    // `LzipReader` takes any failure to read a member header, an I/O error
    // included, for the end of the stream, so errors are caught underneath.
    let mut source = ErrorLatch {
        inner: Reader::new(src),
        failed: None,
    };
    let out = stream_single(&mut source, budget, visit, "lzip-content", |r| {
        Ok(Box::new(lzma_rust2::LzipReader::new(r)) as Box<dyn Read + '_>)
    })?;
    match (out, source.failed) {
        (None, Some(e)) => Err(LimitHit::corrupt(format!("lzip: read failed: {e}"))),
        (out, _) => Ok(out),
    }
}

/// Passes reads and seeks through, keeping the first read error for a caller
/// whose decoder does not report it.
struct ErrorLatch<R> {
    inner: R,
    failed: Option<io::Error>,
}

impl<R: Read> Read for ErrorLatch<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|e| {
            if e.kind() != io::ErrorKind::Interrupted && self.failed.is_none() {
                self.failed = Some(io::Error::new(e.kind(), e.to_string()));
            }
        })
    }
}

impl<R: Seek> Seek for ErrorLatch<R> {
    fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}
