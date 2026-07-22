#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// Streaming cab extraction (pattern A): each CFFOLDER is decoded as a
/// forward-only [`FolderReader`] and each file is handed the visitor as a
/// `take(uncompressed_size)` window — the decompressed folder is never buffered.
/// Files are emitted folder-by-folder in offset order.
pub(crate) fn stream_cab<R: Read + Seek, T>(
    source: &mut R,
    budget: &mut Budget,
    visit: crate::stream::StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::formats::cab_parse::cabinet::Cabinet;
    use crate::formats::cab_parse::folder::FolderReader;
    use crate::stream::{visit_member, MemberMeta};
    let (folder_metas, files) =
        Cabinet::layout(source).map_err(|e| LimitHit::new(format!("cab: {e}")))?;
    let max_buffer = budget.limits.max_buffer_bytes;
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
            max_buffer,
        )
        .map_err(|e| LimitHit::new(format!("cab folder: {e}")))?;
        let mut pos = 0u64;
        for f in folder_files {
            let want = f.data_offset as u64;
            // Both of these are members the cabinet's own directory names, so
            // they exist; this reader just cannot reach them. Reporting is the
            // whole difference between "no malware here" and "did not look".
            if want < pos {
                budget.count_entry()?;
                let m = MemberMeta {
                    name: f.name().to_string(),
                    comp_size: f.uncompressed_size as u64,
                    encrypted: false,
                    unsupported: Some(
                        "CAB member lies before the current position in its folder \
                         (this walker reads forward only)",
                    ),
                };
                if let Some(t) = visit(&m, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            }
            let skipped = skip_forward(&mut reader, want - pos);
            pos += skipped;
            if pos < want {
                budget.count_entry()?;
                let m = MemberMeta {
                    name: f.name().to_string(),
                    comp_size: f.uncompressed_size as u64,
                    encrypted: false,
                    unsupported: Some("CAB folder ended before this member's offset"),
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
                encrypted: false,
                unsupported: None,
            };
            let r = {
                let mut window = (&mut reader).take(f.uncompressed_size as u64);
                let out = visit_member(&meta_m, &mut window, budget, visit)?;
                // Drain any bytes the visitor left so `pos` advances by the full
                // size and the next file lands at the right offset.
                let _ = std::io::copy(&mut window, &mut std::io::sink());
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

/// Read and discard up to `n` bytes; returns how many were skipped.
fn skip_forward<R: Read>(r: &mut R, n: u64) -> u64 {
    let mut skipped = 0u64;
    let mut buf = [0u8; 8192];
    while skipped < n {
        let want = ((n - skipped).min(buf.len() as u64)) as usize;
        match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(k) => skipped += k as u64,
            Err(_) => break,
        }
    }
    skipped
}

pub(crate) fn extract_cab<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let patched = repair_cab_size(data);
    let src: &[u8] = patched.as_deref().unwrap_or(data);
    let mut cursor = Cursor::new(src);
    let cabinet = crate::formats::cab_parse::cabinet::Cabinet::new(
        &mut cursor,
        budget.limits.max_buffer_bytes,
    )
    .map_err(|e| LimitHit::new(format!("cab: {e}")))?;

    for file_entry in cabinet.file_entries() {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let name = file_entry.name().to_string();
        // By entry, not by name: two members can share a name, and a name lookup
        // would hand back the first one's bytes twice and never the second's.
        let reader = match cabinet.read_entry(file_entry) {
            Ok(r) => r,
            Err(_) => {
                if let Some(r) = visit(
                    Entry::unsupported(name, 0, false, "corrupt CAB member"),
                    budget,
                ) {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        let buf = tolerant_read(reader, cap);
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(name, buf), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

fn tolerant_read<R: Read>(mut r: R, cap: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while (buf.len() as u64) < cap {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = (cap - buf.len() as u64) as usize;
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
            Err(_) => break,
        }
    }
    buf
}

fn repair_cab_size(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 || &data[0..4] != b"MSCF" {
        return None;
    }
    let declared = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
    if declared <= data.len() as u64 {
        return None;
    }
    let mut out = data.to_vec();
    out[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    Some(out)
}
