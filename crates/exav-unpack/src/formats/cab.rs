#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// Walk a cabinet off its source.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    stream_cab(&mut crate::source::Reader::new(src), budget, visit)
}

/// Streaming cab extraction (pattern A): each CFFOLDER is decoded as a
/// forward-only [`FolderReader`] and each file is handed the visitor as a
/// `take(uncompressed_size)` window; the decompressed folder is never buffered.
/// Files are emitted folder-by-folder in offset order, and a file that starts
/// before the reader restarts the folder.
pub(crate) fn stream_cab<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::formats::cab_parse::cabinet::Cabinet;
    use crate::formats::cab_parse::folder::FolderReader;
    use crate::stream::{emit_stream, MemberMeta};
    let (folder_metas, files) =
        Cabinet::layout(source).map_err(|e| LimitHit::new(format!("cab: {e}")))?;
    for (folder_idx, meta) in folder_metas.iter().enumerate() {
        let mut folder_files: Vec<&crate::formats::cab_parse::file::FileEntry> = files
            .iter()
            .filter(|f| f.folder_index as usize == folder_idx)
            .collect();
        folder_files.sort_by_key(|f| f.data_offset);
        if folder_files.is_empty() {
            continue;
        }
        let mut reader = FolderReader::new(
            &mut *source,
            meta.first_data_offset,
            meta.num_data_blocks,
            meta.compression_type,
        )
        .map_err(|e| LimitHit::new(format!("cab folder: {e}")))?;
        let mut pos = 0u64;
        // Set once the folder stream fails: past that, offsets no longer
        // match what the reader would return.
        let mut stalled = false;
        for f in folder_files {
            let want = f.data_offset as u64;
            if stalled {
                budget.count_entry()?;
                let m = MemberMeta {
                    name: f.name().to_string(),
                    comp_size: f.uncompressed_size as u64,
                    size: Some(f.uncompressed_size as u64),
                    encrypted: false,
                    unsupported: Some("CAB folder could not be read up to this member"),
                };
                if let Some(t) = visit(&m, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            }
            // A member starting before the reader shares bytes with the one
            // before it: MSI cabinets list a file installed under two names
            // twice at one offset. Decode the folder again from its start. The
            // bytes decoded twice are charged to the scan budget, which bounds
            // a cabinet built to force a restart per member.
            if want < pos {
                budget.charge_scan(want)?;
                drop(reader);
                reader = FolderReader::new(
                    &mut *source,
                    meta.first_data_offset,
                    meta.num_data_blocks,
                    meta.compression_type,
                )
                .map_err(|e| LimitHit::new(format!("cab folder: {e}")))?;
                pos = 0;
            }
            // A member the cabinet's own directory names exists; when this
            // reader cannot reach it, reporting is the whole difference between
            // "no malware here" and "did not look".
            let (skipped, failed) = skip_forward(&mut reader, want - pos);
            pos += skipped;
            stalled = failed;
            if pos < want {
                budget.count_entry()?;
                let m = MemberMeta {
                    name: f.name().to_string(),
                    comp_size: f.uncompressed_size as u64,
                    size: Some(f.uncompressed_size as u64),
                    encrypted: false,
                    unsupported: Some(if failed {
                        "CAB folder could not be read up to this member"
                    } else {
                        "CAB folder ended before this member's offset"
                    }),
                };
                if let Some(t) = visit(&m, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            }
            budget.count_entry()?;
            let meta_m = MemberMeta {
                name: f.name().to_string(),
                comp_size: f.uncompressed_size as u64,
                size: Some(f.uncompressed_size as u64),
                encrypted: false,
                unsupported: None,
            };
            let r = {
                let mut window = (&mut reader).take(f.uncompressed_size as u64);
                let out = emit_stream(&meta_m, &mut window, budget, visit)?;
                // Drain any bytes the visitor left so `pos` advances by the full
                // size and the next file lands at the right offset.
                stalled = std::io::copy(&mut window, &mut std::io::sink()).is_err();
                out
            };
            pos = want + f.uncompressed_size as u64;
            if let Some(t) = r {
                return Ok(Some(t));
            }
        }
    }
    Ok(None)
}

/// Read and discard up to `n` bytes; returns how many were skipped, and whether
/// the reader failed rather than ended.
fn skip_forward<R: Read>(r: &mut R, n: u64) -> (u64, bool) {
    let mut skipped = 0u64;
    let mut buf = [0u8; 8192];
    while skipped < n {
        let want = ((n - skipped).min(buf.len() as u64)) as usize;
        match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(k) => skipped += k as u64,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (skipped, true),
        }
    }
    (skipped, false)
}
