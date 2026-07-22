//! Temporary files and directories, over `std::fs` alone — test support only.
//!
//! The library itself never writes to disk; its tests do, to build databases and
//! scan targets. Pulling a temp-file crate in for that would put `rustix` and
//! `linux-raw-sys` — thousands of `unsafe` blocks — into every `cargo test`, for
//! a page of code `std::fs` already covers.
//!
//! The security properties a temp file has to have, and how they are met here:
//!
//! * **No pre-created-path attack.** Files are opened with `create_new`, i.e.
//!   `O_CREAT|O_EXCL`, which fails rather than following a symlink an attacker
//!   planted at the guessed path. A collision retries with a fresh name.
//! * **Unpredictable names.** The suffix mixes the process id, a per-process
//!   random seed taken from the standard library's `RandomState` (which the OS
//!   seeds), and a counter, so names cannot be guessed between runs or within
//!   one.
//! * **Not world-readable.** On Unix the file is created `0600`.
//! * **Cleaned up.** Dropping removes the file (or the directory tree); a crash
//!   can leave one behind.
//!
//! `exav-cli` carries the same file — there it is not test-only, the daemon
//! spills oversized streams through it. The two are meant to stay identical.

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-process seed, taken once from the standard library's randomly-seeded
/// hasher. `RandomState` is seeded by the OS, so this is unpredictable across
/// runs without pulling in a random-number dependency.
fn process_seed() -> u64 {
    use std::sync::OnceLock;
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(std::process::id() as u64);
        h.finish()
    })
}

fn next_name(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{prefix}-{:x}-{:x}-{n:x}",
        std::process::id(),
        process_seed()
    )
}

/// A temporary file that deletes itself when dropped.
pub struct TempFile {
    path: PathBuf,
    file: File,
}

impl TempFile {
    /// Create a new temp file in the system temp directory.
    pub fn new() -> io::Result<TempFile> {
        let dir = std::env::temp_dir();
        // A handful of attempts: a collision means another process took the
        // name between generating and creating it, which a fresh counter value
        // resolves.
        let mut last = io::Error::other("could not create a temporary file");
        for _ in 0..16 {
            let path = dir.join(next_name("exav-tmp"));
            let mut opts = OpenOptions::new();
            opts.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&path) {
                Ok(file) => return Ok(TempFile { path, file }),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The open handle, for writing the payload in.
    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn as_file(&self) -> &File {
        &self.file
    }

    /// A second handle positioned at the start, for reading the payload back.
    pub fn reopen(&self) -> io::Result<File> {
        File::open(&self.path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl io::Write for TempFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A temporary directory that removes itself, and its contents, when dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> io::Result<TempDir> {
        let base = std::env::temp_dir();
        let mut last = io::Error::other("could not create a temporary directory");
        for _ in 0..16 {
            let path = base.join(next_name("exav-tmpdir"));
            // `create_dir` fails if the path exists, which is the same
            // exclusivity `create_new` gives for files.
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn a_temp_file_round_trips_and_disappears() {
        let path;
        {
            let mut t = TempFile::new().unwrap();
            path = t.path.clone();
            t.as_file_mut().write_all(b"payload").unwrap();
            let mut back = String::new();
            t.reopen().unwrap().read_to_string(&mut back).unwrap();
            assert_eq!(back, "payload", "a second handle reads what was written");
            assert!(path.exists());
        }
        assert!(!path.exists(), "dropping removes the file");
    }

    #[test]
    fn names_do_not_repeat() {
        let a = TempFile::new().unwrap();
        let b = TempFile::new().unwrap();
        assert_ne!(a.path, b.path);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_not_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempFile::new().unwrap();
        let mode = t.as_file().metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "a scanned payload is not world-readable");
    }

    #[test]
    fn a_temp_dir_takes_its_contents_with_it() {
        let path;
        {
            let d = TempDir::new().unwrap();
            path = d.path().to_path_buf();
            std::fs::write(path.join("inside"), b"x").unwrap();
        }
        assert!(!path.exists(), "dropping removes the tree");
    }
}
