#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_zip(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    extract_zip_from(Cursor::new(data), budget)
}

/// Extract a ZIP from any seekable reader. With a range-backed reader (e.g.
/// HTTP) this reads only the central directory and the entries it extracts,
/// rather than the whole archive.
pub fn extract_zip_from<R: Read + Seek>(
    reader: R,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
    let mut entries = Vec::new();
    for i in 0..zip.len() {
        // Count every central-directory entry, including directories, so a
        // directory-only archive cannot iterate past the file-count budget.
        budget.count_entry()?;
        let mut file = zip
            .by_index(i)
            .map_err(|e| LimitHit::new(format!("zip entry {i}: {e}")))?;
        if !file.is_file() {
            continue;
        }
        let name = file.name().to_string();
        let comp = file.compressed_size();
        let cap = budget.reserve()?;
        let (buf, truncated) =
            bounded_read(&mut file, cap).map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
        if truncated {
            return Err(LimitHit::new(format!("zip member '{name}' exceeds budget")));
        }
        // `comp` is attacker-controlled; the absolute caps above are the real
        // bound. The ratio check is only a fast reject when comp is plausible.
        ratio_guard(comp, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        // Compressed size is meaningful for `.cdb` `FileSizeInContainer`.
        entries.push(Entry {
            comp_size: comp,
            encrypted: false,
            name,
            data: buf,
        });
    }
    Ok(entries)
}

/// Lazy, seekable ZIP reader: yields one [`Entry`] at a time so a range-backed
/// reader (e.g. an HTTP range request over a remote ZIP) only fetches the
/// member currently being read, and the caller can stop early — e.g. on the
/// first detection — without touching later members. This is the seekable
/// counterpart to [`extract`], which buffers everything.
pub struct ZipMembers<R: Read + Seek> {
    zip: zip::ZipArchive<R>,
    next: usize,
}

impl<R: Read + Seek> ZipMembers<R> {
    /// Open a seekable ZIP (reads only the central directory up front).
    pub fn open(reader: R) -> Result<Self, LimitHit> {
        let zip = zip::ZipArchive::new(reader).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
        Ok(Self { zip, next: 0 })
    }

    /// Number of central-directory entries (files and directories).
    pub fn len(&self) -> usize {
        self.zip.len()
    }
    pub fn is_empty(&self) -> bool {
        self.zip.is_empty()
    }

    /// Read and decompress the next *file* member under `budget`; `None` when
    /// the archive is exhausted. Directories are skipped (but still counted
    /// toward the file-count budget).
    pub fn next_member(&mut self, budget: &mut Budget) -> Option<Result<Entry, LimitHit>> {
        while self.next < self.zip.len() {
            let i = self.next;
            self.next += 1;
            if let Err(h) = budget.count_entry() {
                return Some(Err(h));
            }
            let res = (|| -> Result<Option<Entry>, LimitHit> {
                let mut file = self
                    .zip
                    .by_index(i)
                    .map_err(|e| LimitHit::new(format!("zip entry {i}: {e}")))?;
                if !file.is_file() {
                    return Ok(None);
                }
                let name = file.name().to_string();
                let comp = file.compressed_size();
                let cap = budget.reserve()?;
                let (buf, truncated) = bounded_read(&mut file, cap)
                    .map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
                if truncated {
                    return Err(LimitHit::new(format!("zip member '{name}' exceeds budget")));
                }
                ratio_guard(comp, buf.len() as u64, budget)?;
                budget.commit(buf.len() as u64);
                Ok(Some(Entry {
                    comp_size: comp,
                    encrypted: false,
                    name,
                    data: buf,
                }))
            })();
            match res {
                Ok(Some(e)) => return Some(Ok(e)),
                Ok(None) => continue,
                Err(h) => return Some(Err(h)),
            }
        }
        None
    }
}
