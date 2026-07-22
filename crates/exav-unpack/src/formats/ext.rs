//! ext2/ext3/ext4 — walking the filesystem rather than carving the bytes.
//!
//! Same argument as `formats/fat.rs`: a disk image handed to a victim gets
//! mounted, and what they run is a *file* in the filesystem. Carving finds a
//! file whose magic sits at the start of a contiguous run and misses the rest,
//! and ext4 fragments freely — a file written into a hole left by a deleted one
//! lands in two extents, and the first fragment alone will not decompress.
//! Reassembling it needs the inode's block map, which means reading the
//! filesystem.
//!
//! Reading is delegated to the `ext4-view` crate: read-only by construction (it
//! has no write path at all), no `unsafe`, and no dependencies of its own.
//!
//! **This is a forced-materialization site.** `Ext4::load` takes an owned
//! `Box<dyn Ext4Read>`, so the image is copied once — it cannot borrow the
//! caller's buffer. The copy is charged against `max_buffer_bytes` like every
//! other such site, and an image past that budget is reported rather than
//! quietly skipped.

use crate::{Budget, Entry, LimitHit, Sink};

/// Bounds on the tree walk; hitting either is reported, never a quiet stop.
const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: u32 = 32;

/// The superblock magic `0xEF53`, which sits 0x38 bytes into the superblock —
/// itself 1024 bytes into the volume.
pub(crate) fn is_ext(data: &[u8]) -> bool {
    super::sniff::is(data, crate::Format::Ext)
}

pub(crate) fn extract_ext<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_ext(data) {
        return Ok(None);
    }
    // See the module note: the reader must own its bytes.
    let cap = budget.limits.max_buffer_bytes;
    if data.len() as u64 > cap {
        budget.count_entry()?;
        return Ok(visit(
            Entry::unsupported(
                "<ext-filesystem>".to_string(),
                data.len() as u64,
                false,
                "ext filesystem image exceeds the peak-buffer budget, so the \
                 files inside it were not examined",
            ),
            budget,
        ));
    }
    let fs = match ext4_view::Ext4::load(Box::new(data.to_vec())) {
        Ok(fs) => fs,
        Err(e) => {
            // The superblock said ext; failing to mount leaves every file in it
            // unexamined, which must not pass quietly.
            let _ = e;
            budget.count_entry()?;
            return Ok(visit(
                Entry::unsupported(
                    "<ext-filesystem>".to_string(),
                    data.len() as u64,
                    false,
                    "ext filesystem could not be mounted",
                ),
                budget,
            ));
        }
    };

    let mut seen = 0usize;
    let mut stack = vec![("/".to_string(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            budget.count_entry()?;
            if let Some(r) = visit(
                Entry::unsupported(
                    format!("<ext-below-depth-{MAX_DEPTH}>"),
                    0,
                    false,
                    "ext directory tree deeper than exav walks",
                ),
                budget,
            ) {
                return Ok(Some(r));
            }
            continue;
        }
        let entries = match fs.read_dir(dir.as_str()) {
            Ok(e) => e,
            Err(e) => {
                // Everything under an unreadable directory is unreachable.
                let _ = e;
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        format!("<ext-dir:{dir}>"),
                        0,
                        false,
                        "unreadable ext directory; its contents are unreachable",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        format!("<ext-dir:{dir}>"),
                        0,
                        false,
                        "unreadable ext directory entry; the rest of that \
                         directory is unreachable",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                break;
            };
            // A name that is not UTF-8 is still a name a `.cdb` signature may
            // match on; `display()` keeps it printable without inventing bytes.
            let name = entry.file_name().display().to_string();
            if name == "." || name == ".." {
                continue;
            }
            let path = format!("{}{}", dir.trim_end_matches('/'), format_args!("/{name}"));
            seen += 1;
            if seen > MAX_ENTRIES {
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        format!("<ext-entries-beyond-{MAX_ENTRIES}>"),
                        0,
                        false,
                        "too many ext entries to walk them all",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                return Ok(None);
            }
            // `symlink_metadata` rather than `metadata`: a symlink must be seen
            // as a symlink, not silently followed to whatever it points at —
            // which for an absolute target would be a path outside the image.
            let Ok(meta) = fs.symlink_metadata(path.as_str()) else {
                budget.count_entry()?;
                if let Some(r) = visit(
                    Entry::unsupported(
                        path,
                        0,
                        false,
                        "ext inode could not be read, so this file went unexamined",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            };
            if meta.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            // Only regular files hold content. A symlink is a path, and a
            // device/fifo/socket node has no bytes in the image at all — there
            // is nothing here that went unscanned, so nothing to report.
            if meta.file_type() != ext4_view::FileType::Regular {
                continue;
            }

            budget.count_entry()?;
            let declared = meta.len();
            let cap = budget.reserve()?;
            if declared > cap {
                if let Some(r) = visit(
                    Entry::unsupported(
                        path,
                        declared,
                        false,
                        "ext file exceeds the per-member size budget",
                    ),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
            // Reading follows the inode's extent tree / block map, which is the
            // whole point: a fragmented file comes back whole here and does not
            // from a carve.
            let bytes = match fs.read(path.as_str()) {
                Ok(b) => b,
                Err(e) => {
                    let _ = e;
                    if let Some(r) = visit(
                        Entry::unsupported(
                            path,
                            declared,
                            false,
                            "ext file could not be read from its block map",
                        ),
                        budget,
                    ) {
                        return Ok(Some(r));
                    }
                    continue;
                }
            };
            budget.commit(bytes.len() as u64);
            if let Some(r) = visit(Entry::new(path, bytes), budget) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}
