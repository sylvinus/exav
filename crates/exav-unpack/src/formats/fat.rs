//! FAT12/16/32 — walking the filesystem rather than carving the bytes.
//!
//! A disk image handed to a victim is usually mounted, and what they run is a
//! *file* in the filesystem. exav reconstructs the guest disk of every image
//! format it opens, but a raw disk is only a pile of sectors: carving finds a
//! file whose magic sits at the start of a contiguous run, and misses the rest.
//!
//! What that costs, concretely. A FAT image with a zipped payload written to a
//! fresh filesystem is contiguous, and carving reaches it. Write two other files
//! first, delete the middle one, then write the payload — it lands in the hole
//! and continues after, in two runs — and carving finds only the first
//! fragment, which will not decompress. Reassembling that needs the cluster
//! chain, which means reading the filesystem.
//!
//! Reading is delegated to the `fatfs` crate rather than hand-rolled: it carries
//! no `unsafe`, and its only dependencies are `bitflags` and `log`.
//!
//! The volume boot record is also what a partition table is *not* — see
//! `formats/partition.rs`, where mistaking one for the other invents a partition
//! spanning the whole image.

use std::io::Cursor;

use crate::{Budget, Entry, LimitHit, Sink};

/// Bound on the tree walk; hitting it is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: u32 = 32;

/// A read-only view of the image for `fatfs`, whose storage trait requires
/// `Write`. Writing is refused rather than supported, which keeps this
/// zero-copy: wrapping a `Cursor<Vec<u8>>` instead would duplicate the whole
/// reconstructed disk in memory.
struct ReadOnly<'a> {
    inner: Cursor<&'a [u8]>,
}

impl std::io::Read for ReadOnly<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl std::io::Write for ReadOnly<'_> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for ReadOnly<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Does this look like a FAT volume boot record?
///
/// The signature is the same `55 AA` an MBR ends with, so the BIOS Parameter
/// Block has to carry the weight: a printable OEM name, a sector size that is
/// one of four values, and a cluster size that is a power of two. A filesystem
/// type string in one of its two possible places settles it.
pub(crate) fn is_fat(data: &[u8]) -> bool {
    if data.len() < 512 || data.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return false;
    }
    // A jump instruction begins every boot sector.
    if !matches!(data[0], 0xEB | 0xE9) {
        return false;
    }
    let Some(oem) = data.get(3..11) else {
        return false;
    };
    if !oem.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return false;
    }
    let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
    let sectors_per_cluster = data[13];
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        || sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
    {
        return false;
    }
    // FAT12/16 keep the type string at 54, FAT32 at 82.
    let ty12 = data.get(54..59);
    let ty32 = data.get(82..87);
    matches!(ty12, Some(b"FAT12") | Some(b"FAT16") | Some(b"FAT  "))
        || ty12.map(|t| t.starts_with(b"FAT")).unwrap_or(false)
        || matches!(ty32, Some(b"FAT32"))
}

pub(crate) fn extract_fat<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_fat(data) {
        return Ok(None);
    }
    let storage = ReadOnly {
        inner: Cursor::new(data),
    };
    let fs = match fatfs::FileSystem::new(storage, fatfs::FsOptions::new()) {
        Ok(fs) => fs,
        Err(e) => {
            // The boot sector said FAT; failing to mount leaves every file in it
            // unexamined, which must not pass quietly.
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported("<fat-volume>".to_string(), data.len() as u64, false, {
                    let _ = e;
                    "FAT filesystem could not be mounted"
                }),
                budget,
            ));
        }
    };

    let mut seen = 0usize;
    let mut stack = vec![(fs.root_dir(), String::new(), 0u32)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    format!("<fat-below-depth-{MAX_DEPTH}>"),
                    0,
                    false,
                    "FAT directory tree deeper than exav walks",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        for entry in dir.iter() {
            let Ok(entry) = entry else {
                // A directory whose entries stop parsing hides everything after
                // them in that directory.
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        format!("<fat-dir:{prefix}>"),
                        0,
                        false,
                        "unreadable FAT directory entry; the rest of that directory is unreachable",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                break;
            };
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            seen += 1;
            if seen > MAX_ENTRIES {
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        format!("<fat-entries-beyond-{MAX_ENTRIES}>"),
                        0,
                        false,
                        "too many FAT entries to walk them all",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                return Ok(None);
            }
            if entry.is_dir() {
                stack.push((entry.to_dir(), path, depth + 1));
                continue;
            }

            budget.count_entry()?;
            let declared = entry.len();
            let cap = budget.reserve()?;
            if declared > cap {
                if let Some(r) = visit(
                    Entry::unsupported(
                        path,
                        declared,
                        false,
                        "FAT file exceeds the per-member size budget",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            let mut file = entry.to_file();
            let mut buf = Vec::with_capacity(declared as usize);
            // Reading follows the cluster chain, so a fragmented file comes back
            // whole here where a carve would return only its first extent.
            if let Err(e) = std::io::Read::read_to_end(&mut file, &mut buf) {
                let _ = e;
                if let Some(r) = visit(
                    Entry::unsupported(
                        path,
                        declared,
                        false,
                        "FAT file could not be read from its cluster chain",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            budget.commit(buf.len() as u64);
            if let Some(r) = visit(Entry::new(path, buf), budget) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}
