//! Room outside memory for bytes a walk makes, when the host provides it.
//!
//! The library never writes to disk itself. A member too large to hold, or a
//! view of an object too large to hold, has to go somewhere it can be read back
//! at any offset. A host that allows that hands a [`Spill`] in. Without one,
//! what would have needed it is reported as not fully scanned.
//!
//! [`DirSpill`] is a spill that writes to a directory.

use std::io::{Read, Seek};

use crate::source::{BlockCache, CHUNK};

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
pub type Spilled = BlockCache<Box<dyn SpillReader>>;

/// Collects bytes for a spill file a batch at a time.
pub struct SpillBatch {
    file: Box<dyn SpillWriter>,
    batch: Vec<u8>,
    /// Why a write failed. Everything after it is dropped.
    failed: Option<String>,
}

impl SpillBatch {
    pub fn new(file: Box<dyn SpillWriter>) -> Self {
        SpillBatch {
            file,
            batch: Vec::with_capacity(CHUNK),
            failed: None,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.batch.extend_from_slice(bytes);
        if self.batch.len() >= CHUNK {
            self.flush();
        }
    }

    #[inline]
    pub fn push(&mut self, b: u8) {
        self.batch.push(b);
        if self.batch.len() >= CHUNK {
            self.flush();
        }
    }

    /// Why a write failed, once. Nothing is written after a failure.
    pub fn take_failure(&mut self) -> Option<String> {
        self.failed.take()
    }

    fn flush(&mut self) {
        if self.failed.is_none()
            && !self.batch.is_empty()
            && let Err(e) = self.file.write(&self.batch)
        {
            self.failed = Some(e);
        }
        self.batch.clear();
    }

    /// What was written, to read back through a block cache of `cache` =
    /// (block size, capacity).
    pub fn finish(mut self, cache: (usize, usize)) -> Result<Spilled, String> {
        self.flush();
        if let Some(e) = self.failed {
            return Err(e);
        }
        let reader = self.file.finish()?;
        BlockCache::with_sizes(reader, cache.0, cache.1)
            .map_err(|e| format!("spill file unreadable: {e}"))
    }
}

/// Write all of `reader` to a new spill file, and read it back. A read error
/// ends the stream there: what was read before it is kept, and the error is
/// given with it. `Err` says why the spill file could not be made, written or
/// read back.
pub fn spill_stream(
    spill: &dyn Spill,
    reader: &mut dyn Read,
    cache: (usize, usize),
) -> Result<(Spilled, Option<std::io::Error>), String> {
    let mut out = SpillBatch::new(spill.create()?);
    let mut buf = vec![0u8; CHUNK];
    let mut failed = None;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.write(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
        if let Some(e) = out.take_failure() {
            return Err(e);
        }
    }
    Ok((out.finish(cache)?, failed))
}

#[cfg(not(target_family = "wasm"))]
pub use dir::DirSpill;

#[cfg(not(target_family = "wasm"))]
mod dir {
    use super::{Spill, SpillReader, SpillWriter};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, Write};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Spill files in a directory.
    ///
    /// A file is created with `create_new` under an unpredictable name and, on
    /// Unix, mode 0600, so a path planted at a guessed name is not followed and
    /// nobody else reads it. It is unlinked at once on Unix, and elsewhere when
    /// the file is dropped, so nothing is left behind.
    ///
    /// `per_object` bounds the bytes of one file and `total` those of all the
    /// files made by this spill (and its clones) that are still alive. A byte
    /// is charged before it is written. `None` is no bound.
    #[derive(Debug, Clone)]
    pub struct DirSpill {
        dir: PathBuf,
        per_object: Option<u64>,
        total: Option<u64>,
        in_use: Arc<AtomicU64>,
    }

    impl DirSpill {
        /// Spill files in `dir`, with no bound.
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            DirSpill {
                dir: dir.into(),
                per_object: None,
                total: None,
                in_use: Arc::default(),
            }
        }

        /// The most bytes one file may hold.
        pub fn per_object(mut self, max: Option<u64>) -> Self {
            self.per_object = max;
            self
        }

        /// The most bytes all the live files may hold together.
        pub fn total(mut self, max: Option<u64>) -> Self {
            self.total = max;
            self
        }

        /// Bytes held by the files that are alive now.
        pub fn in_use(&self) -> u64 {
            self.in_use.load(Ordering::SeqCst)
        }

        fn open(&self) -> io::Result<DirFile> {
            use std::hash::{BuildHasher, Hasher};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let mut last = io::Error::other("could not create a spill file");
            for _ in 0..16 {
                let mut h = std::collections::hash_map::RandomState::new().build_hasher();
                h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
                let path = self.dir.join(format!(
                    "exav-spill-{:x}-{:x}",
                    std::process::id(),
                    h.finish()
                ));
                let mut opts = OpenOptions::new();
                opts.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                match opts.open(&path) {
                    Ok(file) => {
                        #[cfg(unix)]
                        let _ = std::fs::remove_file(&path);
                        return Ok(DirFile {
                            file,
                            charge: Charge {
                                in_use: Arc::clone(&self.in_use),
                                mine: 0,
                            },
                            per_object: self.per_object,
                            total: self.total,
                            #[cfg(not(unix))]
                            _remove: RemoveOnDrop(path),
                        });
                    }
                    Err(e) => last = e,
                }
            }
            Err(last)
        }
    }

    impl Spill for DirSpill {
        fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
            let file = self
                .open()
                .map_err(|e| format!("spill file in {}: {e}", self.dir.display()))?;
            Ok(Box::new(file))
        }
    }

    /// The share of the total a file holds, given back when it is dropped.
    #[derive(Debug)]
    struct Charge {
        in_use: Arc<AtomicU64>,
        mine: u64,
    }

    impl Drop for Charge {
        fn drop(&mut self) {
            self.in_use.fetch_sub(self.mine, Ordering::SeqCst);
        }
    }

    #[cfg(not(unix))]
    struct RemoveOnDrop(PathBuf);

    #[cfg(not(unix))]
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    struct DirFile {
        file: File,
        charge: Charge,
        per_object: Option<u64>,
        total: Option<u64>,
        /// After `file`, so that it is closed before it is removed.
        #[cfg(not(unix))]
        _remove: RemoveOnDrop,
    }

    impl DirFile {
        /// Reserve `n` more bytes against both bounds.
        fn reserve(&mut self, n: u64) -> Result<(), String> {
            let want = self.charge.mine.saturating_add(n);
            if let Some(max) = self.per_object
                && want > max
            {
                return Err(format!("over the {max}-byte spill limit for one object"));
            }
            let used = &self.charge.in_use;
            let mut now = used.load(Ordering::SeqCst);
            loop {
                let next = now.saturating_add(n);
                if let Some(max) = self.total
                    && next > max
                {
                    return Err(format!(
                        "no room in the {max}-byte spill budget ({now} in use)"
                    ));
                }
                // Compare and swap: two files written at once must not both see
                // room that only one of them can have.
                match used.compare_exchange_weak(now, next, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => break,
                    Err(seen) => now = seen,
                }
            }
            self.charge.mine = want;
            Ok(())
        }
    }

    impl SpillWriter for DirFile {
        fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.reserve(bytes.len() as u64)?;
            self.file
                .write_all(bytes)
                .map_err(|e| format!("spill file: {e}"))
        }

        fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
            let DirFile {
                mut file,
                charge,
                #[cfg(not(unix))]
                _remove,
                ..
            } = *self;
            file.rewind().map_err(|e| format!("spill file: {e}"))?;
            Ok(Box::new(Back {
                file,
                _charge: charge,
                #[cfg(not(unix))]
                _remove,
            }))
        }
    }

    /// A spill file being read back. Its share of the total is held until this
    /// is dropped.
    struct Back {
        file: File,
        _charge: Charge,
        #[cfg(not(unix))]
        _remove: RemoveOnDrop,
    }

    impl Read for Back {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.file.read(buf)
        }
    }

    impl Seek for Back {
        fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
            self.file.seek(to)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::source::ByteSource;
        use std::sync::atomic::AtomicUsize;

        /// A new empty directory, removed with its guard.
        struct Dir(PathBuf);

        impl Dir {
            fn new() -> Dir {
                static N: AtomicUsize = AtomicUsize::new(0);
                let dir = std::env::temp_dir().join(format!(
                    "exav-dirspill-test-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir(&dir).unwrap();
                Dir(dir)
            }

            fn files(&self) -> usize {
                std::fs::read_dir(&self.0).unwrap().count()
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn bytes(n: usize) -> Vec<u8> {
            (0..n).map(|i| (i * 7 % 251) as u8).collect()
        }

        #[test]
        fn what_is_written_reads_back_at_any_offset() {
            let dir = Dir::new();
            let spill = DirSpill::new(&dir.0);
            let data = bytes(3 * crate::source::CHUNK + 11);
            let (back, failed) =
                crate::spill::spill_stream(&spill, &mut io::Cursor::new(&data), (4096, 1 << 20))
                    .unwrap();
            assert!(failed.is_none());
            assert_eq!(back.len(), data.len());
            assert_eq!(&back.window(0, data.len())[..], &data[..]);
            let at = crate::source::CHUNK + 5;
            assert_eq!(&back.window(at, 100)[..], &data[at..at + 100]);
        }

        #[cfg(unix)]
        #[test]
        fn a_file_is_private_and_has_no_name_once_made() {
            use std::os::unix::fs::PermissionsExt;
            let dir = Dir::new();
            let spill = DirSpill::new(&dir.0);
            let file = spill.open().unwrap();
            assert_eq!(dir.files(), 0, "unlinked at once");
            let mode = file.file.metadata().unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        #[test]
        fn one_file_over_its_limit_is_refused_with_the_limit() {
            let dir = Dir::new();
            let spill = DirSpill::new(&dir.0).per_object(Some(100));
            let mut file = spill.create().unwrap();
            file.write(&bytes(60)).unwrap();
            let e = file.write(&bytes(60)).unwrap_err();
            assert!(e.contains("100-byte") && e.contains("one object"), "{e}");
            // Another file has its own share.
            spill.create().unwrap().write(&bytes(100)).unwrap();
        }

        #[test]
        fn the_total_is_shared_and_given_back_when_a_reader_is_dropped() {
            let dir = Dir::new();
            let spill = DirSpill::new(&dir.0).total(Some(100));
            let mut a = spill.create().unwrap();
            a.write(&bytes(70)).unwrap();
            assert_eq!(spill.in_use(), 70);
            let mut b = spill.create().unwrap();
            let e = b.write(&bytes(40)).unwrap_err();
            assert!(e.contains("100-byte") && e.contains("70 in use"), "{e}");
            assert_eq!(spill.in_use(), 70, "a refused write charges nothing");
            // Written, read back and dropped: the share is free again.
            let reader = a.finish().unwrap();
            assert_eq!(spill.in_use(), 70, "held while it is read");
            drop(reader);
            assert_eq!(spill.in_use(), 0);
            b.write(&bytes(100)).unwrap();
        }

        #[test]
        fn a_directory_that_is_not_there_says_so() {
            let dir = Dir::new();
            let spill = DirSpill::new(dir.0.join("missing"));
            let e = spill.create().err().expect("no file");
            assert!(e.contains("missing"), "{e}");
        }
    }
}

/// A spill held in memory, for tests.
#[cfg(any(test, feature = "test-util"))]
pub use mem::MemSpill;

#[cfg(any(test, feature = "test-util"))]
mod mem {
    use super::{Spill, SpillReader, SpillWriter};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A spill held in memory, with a byte limit for each file if wanted.
    #[derive(Debug, Default)]
    pub struct MemSpill {
        file_limit: Option<usize>,
        made: AtomicUsize,
    }

    impl MemSpill {
        /// Files with no limit.
        pub fn new() -> Self {
            Self::default()
        }

        /// Files that refuse a write past `bytes` in total.
        pub fn with_file_limit(bytes: usize) -> Self {
            MemSpill {
                file_limit: Some(bytes),
                made: AtomicUsize::new(0),
            }
        }

        /// How many files were made.
        pub fn made(&self) -> usize {
            self.made.load(Ordering::SeqCst)
        }
    }

    struct MemWriter {
        data: Vec<u8>,
        limit: Option<usize>,
    }

    impl Spill for MemSpill {
        fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
            self.made.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(MemWriter {
                data: Vec::new(),
                limit: self.file_limit,
            }))
        }
    }

    impl SpillWriter for MemWriter {
        fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
            if self
                .limit
                .is_some_and(|max| self.data.len() + bytes.len() > max)
            {
                return Err("spill budget".into());
            }
            self.data.extend_from_slice(bytes);
            Ok(())
        }

        fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
            Ok(Box::new(Cursor::new(self.data)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ByteSource;
    use std::io::Cursor;

    #[test]
    fn a_stream_spilled_reads_back_whole_or_says_why_not() {
        let data: Vec<u8> = (0..3 * CHUNK + 5).map(|i| i as u8).collect();
        let spill = MemSpill::new();
        let (back, failed) =
            spill_stream(&spill, &mut Cursor::new(&data), (64 * 1024, 8 << 20)).unwrap();
        assert!(failed.is_none());
        assert_eq!(back.window(0, back.len()), &data[..]);
        let small = MemSpill::with_file_limit(CHUNK);
        assert!(spill_stream(&small, &mut Cursor::new(&data), (64 * 1024, 8 << 20)).is_err());
    }

    /// On a 32-bit target a spill file past 4 GiB cannot be read back whole:
    /// the spill is refused with that reason, not read cut short.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn a_spill_file_past_4_gib_is_refused_with_its_reason() {
        struct Huge;
        impl Read for Huge {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
        }
        impl Seek for Huge {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Ok(5 << 30)
            }
        }
        struct HugeSpill;
        struct HugeWriter;
        impl Spill for HugeSpill {
            fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
                Ok(Box::new(HugeWriter))
            }
        }
        impl SpillWriter for HugeWriter {
            fn write(&mut self, _: &[u8]) -> Result<(), String> {
                Ok(())
            }
            fn finish(self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
                Ok(Box::new(Huge))
            }
        }
        let e = spill_stream(&HugeSpill, &mut Cursor::new(vec![0u8; 10]), (4096, 1 << 20))
            .err()
            .expect("refused");
        assert!(e.contains("can address"), "{e}");
    }

    /// A stream that fails part way: what was read before the error is kept.
    #[test]
    fn a_stream_that_fails_part_way_is_spilled_up_to_the_error() {
        let data: Vec<u8> = (0..2 * CHUNK + 7).map(|i| i as u8).collect();
        let mut reader = Cursor::new(&data).chain(FailingRead);
        let spill = MemSpill::new();
        let (back, failed) = spill_stream(&spill, &mut reader, (64 * 1024, 8 << 20)).unwrap();
        assert_eq!(
            failed.map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(back.window(0, back.len()), &data[..]);
    }

    #[test]
    fn bytes_pushed_one_at_a_time_read_back_whole() {
        let data: Vec<u8> = (0..2 * CHUNK + 3).map(|i| (i * 7) as u8).collect();
        let mut out = SpillBatch::new(MemSpill::new().create().unwrap());
        for &b in &data {
            out.push(b);
        }
        assert!(out.take_failure().is_none());
        let back = out.finish((4096, 1 << 20)).unwrap();
        assert_eq!(back.window(0, back.len()), &data[..]);
    }

    /// A write that fails is told by `take_failure`, and by `finish` if it was
    /// not taken.
    #[test]
    fn a_write_that_fails_is_reported() {
        let new = || SpillBatch::new(MemSpill::with_file_limit(CHUNK).create().unwrap());
        let mut out = new();
        out.write(&vec![1u8; CHUNK]);
        assert!(out.take_failure().is_none(), "within the limit");
        out.write(&vec![2u8; CHUNK]);
        assert_eq!(out.take_failure().as_deref(), Some("spill budget"));
        assert!(out.take_failure().is_none(), "told once");
        let mut out = new();
        out.write(&vec![1u8; 2 * CHUNK]);
        assert_eq!(
            out.finish((4096, 1 << 20)).err().as_deref(),
            Some("spill budget")
        );
    }

    struct FailingRead;

    impl Read for FailingRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::UnexpectedEof.into())
        }
    }
}
