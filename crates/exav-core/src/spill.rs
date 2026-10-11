//! Room outside memory for bytes a scan makes, when the host provides it.
//!
//! The library never writes to disk itself. A scan of an object too large to
//! hold makes views of it (its normalised text) and meets members too large to
//! hold, and those have to go somewhere they can be read back at any offset. A
//! host that allows that hands a [`Spill`] in [`crate::ScanOptions::spill`].
//! Without one, what would have needed it is reported as not fully scanned.

use std::io::{Read, Seek};

use crate::byte_source::{BlockCache, CHUNK};

/// Makes spill files.
pub trait Spill: Send + Sync {
    /// A new, empty spill file, or why there cannot be one.
    fn create(&self) -> Result<Box<dyn SpillWriter>, String>;
}

/// A spill file being written.
pub trait SpillWriter {
    /// Append `bytes`, or say why they cannot be kept.
    fn write(&mut self, bytes: &[u8]) -> Result<(), String>;

    /// Stop writing and read back what was written. The file lasts as long as
    /// the reader.
    fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String>;
}

/// A spill file read back.
pub trait SpillReader: Read + Seek {}

impl<T: Read + Seek> SpillReader for T {}

/// A spill file read back through a block cache.
pub(crate) type Spilled = BlockCache<Box<dyn SpillReader>>;

/// Collects bytes for a spill file a batch at a time.
pub(crate) struct SpillOut {
    file: Box<dyn SpillWriter>,
    batch: Vec<u8>,
    last: Option<u8>,
    /// Why a write failed. Everything after it is dropped.
    failed: Option<String>,
}

impl SpillOut {
    pub(crate) fn new(file: Box<dyn SpillWriter>) -> Self {
        SpillOut {
            file,
            batch: Vec::with_capacity(CHUNK),
            last: None,
            failed: None,
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) {
        self.batch.extend_from_slice(bytes);
        if self.batch.len() >= CHUNK {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.failed.is_none() && !self.batch.is_empty() {
            if let Err(e) = self.file.write(&self.batch) {
                self.failed = Some(e);
            }
        }
        self.batch.clear();
    }

    /// What was written, to read back.
    pub(crate) fn finish(mut self) -> Result<Spilled, String> {
        self.flush();
        if let Some(e) = self.failed {
            return Err(e);
        }
        let reader = self.file.finish()?;
        BlockCache::new(reader).map_err(|e| format!("spill file unreadable: {e}"))
    }
}

impl crate::normalize::Out for SpillOut {
    #[inline]
    fn push(&mut self, b: u8) {
        self.batch.push(b);
        self.last = Some(b);
        if self.batch.len() >= CHUNK {
            self.flush();
        }
    }

    fn last(&self) -> Option<u8> {
        self.last
    }
}

/// Why a stream could not be spilled.
#[derive(Debug)]
pub(crate) enum SpillStreamError {
    /// Reading the stream failed.
    Read(std::io::Error),
    /// The spill file could not be made, written or read back.
    Spill(String),
}

/// Write all of `reader` to a new spill file, and read it back.
pub(crate) fn spill_stream(
    spill: &dyn Spill,
    reader: &mut dyn Read,
) -> Result<Spilled, SpillStreamError> {
    let mut out = SpillOut::new(spill.create().map_err(SpillStreamError::Spill)?);
    let mut buf = vec![0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.write(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SpillStreamError::Read(e)),
        }
        if let Some(e) = out.failed.take() {
            return Err(SpillStreamError::Spill(e));
        }
    }
    out.finish().map_err(SpillStreamError::Spill)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::byte_source::ByteSource;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    /// A spill held in memory, with a byte budget, for tests.
    pub(crate) struct MemSpill {
        pub budget: usize,
        pub made: Arc<Mutex<usize>>,
    }

    struct MemWriter(Vec<u8>, usize);

    impl Spill for MemSpill {
        fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
            *self.made.lock().unwrap() += 1;
            Ok(Box::new(MemWriter(Vec::new(), self.budget)))
        }
    }

    impl SpillWriter for MemWriter {
        fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
            if self.0.len() + bytes.len() > self.1 {
                return Err("spill budget".into());
            }
            self.0.extend_from_slice(bytes);
            Ok(())
        }

        fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
            Ok(Box::new(Cursor::new(self.0)))
        }
    }

    #[test]
    fn a_stream_spilled_reads_back_whole_or_says_why_not() {
        let data: Vec<u8> = (0..3 * CHUNK + 5).map(|i| i as u8).collect();
        let spill = MemSpill {
            budget: usize::MAX,
            made: Arc::default(),
        };
        let back = spill_stream(&spill, &mut Cursor::new(&data)).unwrap();
        assert_eq!(back.window(0, back.len()), &data[..]);
        let small = MemSpill {
            budget: CHUNK,
            made: Arc::default(),
        };
        assert!(spill_stream(&small, &mut Cursor::new(&data)).is_err());
    }
}
