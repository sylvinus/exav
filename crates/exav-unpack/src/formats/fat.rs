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

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

use std::io::{Read, Seek};

use crate::source::{ByteSource, Reader};
use crate::stream::Visit;
use crate::{Budget, Entry, LimitHit, Sink};

/// Bound on the tree walk; hitting it is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: u32 = 32;

/// A read-only view of the volume for `fatfs`, whose storage trait requires
/// `Write`. Writing is refused rather than supported. The volume is read where
/// `fatfs` goes, never copied.
struct ReadOnly<D>(D);

impl<D: Read> Read for ReadOnly<D> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<D> std::io::Write for ReadOnly<D> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<D: Seek> Seek for ReadOnly<D> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

/// Runs a read of `fatfs`, a panic of its own standing for the read that failed.
///
/// `fatfs` subtracts 2 from a cluster number it takes from the volume (a
/// directory entry's, or the next one in a chain) without looking at it, so a
/// chain through cluster 1 panics where a read error would do. Without this
/// the panic reaches the walk's boundary, which ends the whole volume as
/// unreadable; here it ends that directory or that file, and the rest of the
/// volume is walked.
// Never inlined: the fuzz targets let a panic through by this frame's name.
#[inline(never)]
fn contained<R>(read: impl FnOnce() -> std::io::Result<R>) -> std::io::Result<R> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(read)).unwrap_or_else(|_| {
        Err(std::io::Error::other(
            "the FAT reader panicked on this volume",
        ))
    })
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

/// Walk a raw FAT volume.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    super::volumes::entries(budget, visit, "", |budget, sink| {
        walk_volume(Reader::new(src), src.len() as u64, budget, sink)
    })
}

/// Walk the FAT volume `disk`, which is `len` bytes long, handing each file to
/// `visit`.
pub(crate) fn walk_volume<D: Read + Seek, R>(
    mut disk: D,
    len: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if len < 512 {
        return Ok(None);
    }
    let mut boot = [0u8; 512];
    // `fatfs` takes the volume at its start, so the boot sector is read and
    // the volume rewound.
    disk.seek(std::io::SeekFrom::Start(0))
        .and_then(|_| disk.read_exact(&mut boot))
        .and_then(|_| disk.seek(std::io::SeekFrom::Start(0)))
        .map_err(|e| LimitHit::corrupt(format!("FAT volume: {e}")))?;
    if !is_fat(&boot) {
        return Ok(None);
    }
    let fs = match fatfs::FileSystem::new(ReadOnly(disk), fatfs::FsOptions::new()) {
        Ok(fs) => fs,
        Err(e) => {
            // The boot sector said FAT; failing to mount leaves every file in it
            // unexamined, which must not pass quietly.
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported("<fat-volume>".to_string(), len, false, {
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
        let mut entries = dir.iter();
        while let Some(entry) = contained(|| entries.next().transpose()).transpose() {
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
            seen = seen.saturating_add(1);
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
                stack.push((entry.to_dir(), path, depth.saturating_add(1)));
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
            let mut buf = Vec::with_capacity(crate::cap_prealloc(crate::bytes::to_usize(declared)));
            // Reading follows the cluster chain, so a fragmented file comes back
            // whole here where a carve would return only its first extent.
            if let Err(e) = contained(|| std::io::Read::read_to_end(&mut file, &mut buf)) {
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
