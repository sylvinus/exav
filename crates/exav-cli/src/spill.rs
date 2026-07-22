//! Where and how an object too large to hold in RAM is buffered while it is
//! scanned.
//!
//! Container-aware scanning needs to *seek*: a ZIP's directory is at its end, so
//! an archive that can only be read forward cannot be opened at all. Every
//! streaming surface — `INSTREAM`/`EXINSTREAM`, the CLI's stdin, an ICAP
//! encapsulated body — therefore has to materialise what it receives before it
//! can scan it. Small objects sit in RAM; past a threshold they go to a temp
//! file, which is what keeps a listener's memory bounded by the threshold rather
//! than by whatever a client chooses to send.
//!
//! That trade moves the exposure from RAM to disk, so the disk side is bounded
//! too, at three levels:
//!
//! * [`SpillConfig::threshold`] — how much stays in RAM before any file exists.
//! * [`SpillConfig::max_object`] — the largest single object that may be spilled.
//! * [`SpillConfig::max_total`] — how much every in-flight object *together* may
//!   occupy, across the whole process.
//!
//! The third is the one a per-object limit cannot replace. A listener serving a
//! hundred connections with a 2 GiB per-object cap has a 200 GiB worst case, and
//! filling the temp filesystem is a denial of service against the host — one
//! that outlives the connection that caused it and takes down everything else
//! sharing that filesystem.
//!
//! Exceeding a budget is not an I/O failure and must not be reported as one. The
//! object is simply one exav could not examine, which is a verdict every surface
//! already knows how to say ([`SpillError::Budget`] → `UNSCANNABLE`). Dropping
//! the connection instead would leave the client with no answer at all, and a
//! client with no answer is a client that decides for itself.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::tmpfile::TempFile;

/// Bytes of an object held in RAM before a temp file is opened for it.
pub(crate) const DEFAULT_THRESHOLD: u64 = 16 * 1024 * 1024;

/// Ceiling on what one object may write to the temp filesystem. clamd bounds the
/// same thing with `StreamMaxLength`.
///
/// Generous, because the point is to stop an unbounded sender rather than to
/// second-guess a large upload: an object this size is already far past what any
/// scan budget will let the engine look at.
pub(crate) const DEFAULT_MAX_OBJECT: u64 = 2 * 1024 * 1024 * 1024;

/// Ceiling on the temp space every in-flight object holds at once.
pub(crate) const DEFAULT_MAX_TOTAL: u64 = 8 * 1024 * 1024 * 1024;

/// The spill settings, fixed for the life of the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpillConfig {
    /// Whether an object may go to disk at all.
    ///
    /// Off, nothing is ever written to a temp file and
    /// [`threshold`](Self::threshold) becomes a hard per-object memory ceiling:
    /// an object that outgrows it is `UNSCANNABLE`, because there is nowhere
    /// left to put it. That is the shape a read-only root filesystem needs, and
    /// the one a deployment picks when it would rather refuse a large object
    /// than let a scanned payload touch a disk at all.
    pub enabled: bool,
    /// Directory the temp files are created in. `None` is the platform's temp
    /// directory, i.e. `TMPDIR` where the platform reads one.
    pub dir: Option<PathBuf>,
    /// Bytes kept in RAM before an object spills.
    pub threshold: u64,
    /// Largest single object that may be spilled. `u64::MAX` is no ceiling.
    pub max_object: u64,
    /// Largest total the process may hold spilled at one moment. `u64::MAX` is
    /// no ceiling.
    pub max_total: u64,
}

impl Default for SpillConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            threshold: DEFAULT_THRESHOLD,
            max_object: DEFAULT_MAX_OBJECT,
            max_total: DEFAULT_MAX_TOTAL,
        }
    }
}

static CONFIG: OnceLock<SpillConfig> = OnceLock::new();

/// Bytes currently held in temp files across the process. A [`SpillFile`]
/// charges this as it writes and releases its share when it is dropped, which is
/// when the scan that needed it is over.
static IN_USE: AtomicU64 = AtomicU64::new(0);

/// Install the settings. Called once, from the startup path, before any listener
/// accepts anything.
///
/// Later calls are ignored rather than refused: the settings are read from one
/// place at startup, and a second caller would be a bug here rather than an
/// operator error worth reporting.
pub(crate) fn configure(cfg: SpillConfig) {
    let _ = CONFIG.set(cfg);
}

/// The settings in force, defaulted for any caller that never configured them
/// (unit tests, and the library-style entry points).
pub(crate) fn config() -> &'static SpillConfig {
    CONFIG.get_or_init(SpillConfig::default)
}

/// Bytes currently spilled, for a caller that reports on the process.
pub(crate) fn in_use() -> u64 {
    IN_USE.load(Ordering::Relaxed)
}

/// Why an object could not be buffered.
#[derive(Debug)]
pub(crate) enum SpillError {
    /// A configured budget refused it. The object is unscannable; the connection
    /// is fine and owes the client a verdict.
    Budget(String),
    /// The temp filesystem failed — full, read-only, or absent.
    Io(io::Error),
}

impl std::fmt::Display for SpillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget(reason) => f.write_str(reason),
            Self::Io(e) => write!(f, "temporary file: {e}"),
        }
    }
}

impl std::error::Error for SpillError {}

impl From<io::Error> for SpillError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// A temp file holding one object, plus that object's share of the process-wide
/// budget.
///
/// The share is released by `Drop`, so it is tied to the payload's lifetime
/// rather than to any code path remembering to give it back — including the
/// paths that leave early because a scan failed or a client vanished.
pub(crate) struct SpillFile {
    file: TempFile,
    /// Bytes of [`IN_USE`] this file is accountable for.
    charged: u64,
}

impl SpillFile {
    /// Open a spill file in the configured directory.
    ///
    /// The single place a temp file comes into existence, which is what makes
    /// `--spill-dir off` a guarantee rather than a hope: with spilling off there
    /// is no path from here to a file, so no scanned byte reaches a disk.
    pub(crate) fn create() -> Result<Self, SpillError> {
        let cfg = config();
        if !cfg.enabled {
            return Err(SpillError::Budget(format!(
                "object exceeds the {} that fits in memory and spilling to disk is off \
                 (--spill-dir off)",
                human_bytes(cfg.threshold)
            )));
        }
        let file = match &cfg.dir {
            Some(dir) => TempFile::new_in(dir)?,
            None => TempFile::new()?,
        };
        Ok(Self { file, charged: 0 })
    }

    /// Append to the file, charging the budgets first.
    ///
    /// Charged before the write, not after: a budget checked afterwards has
    /// already been exceeded by the time it says so.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), SpillError> {
        self.charge(bytes.len() as u64)?;
        self.file.as_file_mut().write_all(bytes)?;
        Ok(())
    }

    /// Reserve `n` more bytes against the per-object and process-wide budgets.
    fn charge(&mut self, n: u64) -> Result<(), SpillError> {
        let cfg = config();
        let want = self.charged.saturating_add(n);
        if want > cfg.max_object {
            return Err(SpillError::Budget(format!(
                "object exceeds the {} spill ceiling for one object",
                human_bytes(cfg.max_object)
            )));
        }
        // Compare-and-swap rather than a load followed by an add: two
        // connections spilling at once would both read a total under the
        // ceiling and both add to it, and the budget that exists to bound
        // concurrent use would be the one thing concurrency defeats.
        IN_USE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                let total = used.saturating_add(n);
                (total <= cfg.max_total).then_some(total)
            })
            .map_err(|_| {
                // The amount in use is the actionable half: it says whether the
                // budget is too small for the load or one object is hogging it.
                SpillError::Budget(format!(
                    "no room in the {} process-wide spill budget ({} in use)",
                    human_bytes(cfg.max_total),
                    human_bytes(in_use())
                ))
            })?;
        self.charged = want;
        Ok(())
    }

    /// A handle positioned at the start, for reading the object back.
    pub(crate) fn reopen(&self) -> io::Result<std::fs::File> {
        self.file.reopen()
    }

    /// The bytes written so far.
    pub(crate) fn len(&self) -> io::Result<u64> {
        Ok(self.file.as_file().metadata()?.len())
    }
}

impl Drop for SpillFile {
    fn drop(&mut self) {
        IN_USE.fetch_sub(self.charged, Ordering::SeqCst);
    }
}

/// Render a byte count the way an operator writes one, so a message about a
/// 64 KiB budget does not read "0 MiB".
pub(crate) fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB && n.is_multiple_of(GIB) {
        format!("{} GiB", n / GIB)
    } else if n >= MIB && n.is_multiple_of(MIB) {
        format!("{} MiB", n / MIB)
    } else if n >= KIB && n.is_multiple_of(KIB) {
        format!("{} KiB", n / KIB)
    } else {
        format!("{n} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_byte_counts_an_operator_recognises() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(999), "999 bytes");
        assert_eq!(human_bytes(64 * 1024), "64 KiB");
        assert_eq!(human_bytes(16 * 1024 * 1024), "16 MiB");
        assert_eq!(human_bytes(2 * 1024 * 1024 * 1024), "2 GiB");
        // Not a round multiple: falls back rather than lying by rounding.
        assert_eq!(human_bytes(1024 * 1024 + 1), "1048577 bytes");
    }

    #[test]
    fn the_defaults_bound_ram_then_one_object_then_the_process() {
        let d = SpillConfig::default();
        assert_eq!(d.dir, None, "the platform temp directory unless told");
        assert!(
            d.threshold < d.max_object && d.max_object <= d.max_total,
            "each budget has to leave room for the one inside it: {d:?}"
        );
    }

    /// The budget is released when the payload is, not when some code path
    /// remembers to give it back — including the paths that leave early.
    #[test]
    fn a_dropped_payload_returns_its_share_of_the_budget() {
        let before = in_use();
        {
            let mut f = SpillFile::create().expect("a temp file");
            f.write_all(&[b'x'; 4096]).expect("write");
            assert_eq!(in_use(), before + 4096);
        }
        assert_eq!(in_use(), before, "the share outlived the payload");
    }

    #[test]
    fn a_budget_refusal_is_not_an_io_error() {
        // The distinction the callers act on: one is a verdict the client is
        // owed, the other is a broken host.
        let e = SpillError::Budget("no room".to_string());
        assert!(matches!(e, SpillError::Budget(_)));
        assert_eq!(e.to_string(), "no room");
    }
}
