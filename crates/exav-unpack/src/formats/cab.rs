#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// Walk a cabinet off its source.
pub(crate) fn walk(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    stream_cab(&mut crate::source::Reader::new(src), budget, visit)
}

/// Streaming cab extraction (pattern A): each CFFOLDER is decoded as a
/// forward-only [`FolderReader`] and each file is handed the visitor as a
/// `take(uncompressed_size)` window; the decompressed folder is never buffered.
/// Files are emitted folder-by-folder in offset order, and a file that starts
/// before the reader restarts the folder.
pub(crate) fn stream_cab<R: Read + Seek>(
    source: &mut R,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    use crate::formats::cab_parse::cabinet::Cabinet;
    use crate::formats::cab_parse::folder::FolderReader;
    use crate::stream::{MemberMeta, emit_stream};
    let (folder_metas, files) =
        Cabinet::layout(source).map_err(|e| LimitHit::corrupt(format!("cab: {e}")))?;
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
        .map_err(|e| LimitHit::corrupt(format!("cab folder: {e}")))?;
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
                    unsupported: Some("CAB folder could not be read up to this member"),
                    ..MemberMeta::default()
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
                .map_err(|e| LimitHit::corrupt(format!("cab folder: {e}")))?;
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
                    unsupported: Some(if failed {
                        "CAB folder could not be read up to this member"
                    } else {
                        "CAB folder ended before this member's offset"
                    }),
                    ..MemberMeta::default()
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
                ..MemberMeta::default()
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
    // A file in no folder of this cabinet runs from or into another one of its
    // set (`iFolder` 0xFFFD to 0xFFFF), or names a folder that is not there.
    // Its bytes are not here, and it is not for a scan to pass over it.
    for f in files
        .iter()
        .filter(|f| f.folder_index as usize >= folder_metas.len())
    {
        budget.count_entry()?;
        let m = MemberMeta {
            name: f.name().to_string(),
            comp_size: f.uncompressed_size as u64,
            size: Some(f.uncompressed_size as u64),
            unsupported: Some(if f.folder_index >= 0xFFFD {
                "CAB member continues in another cabinet of its set"
            } else {
                "CAB member names a folder the cabinet does not have"
            }),
            ..MemberMeta::default()
        };
        if let Some(t) = visit(&m, None, budget) {
            return Ok(Some(t));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, SeekFrom, Write};

    /// A source that cannot seek to one place: the start of the folder's data.
    struct NoSeekTo {
        inner: Cursor<Vec<u8>>,
        at: u64,
    }

    impl Read for NoSeekTo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Seek for NoSeekTo {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            if to == SeekFrom::Start(self.at) {
                return Err(std::io::Error::other("cannot seek there"));
            }
            self.inner.seek(to)
        }
    }

    /// A folder that cannot be opened is an unreadable cabinet: damage, like
    /// the directory, not a limit.
    #[test]
    fn a_folder_that_cannot_be_opened_is_damage_not_a_limit() {
        let mut builder = ::cab::CabinetBuilder::new();
        builder
            .add_folder(::cab::CompressionType::None)
            .add_file("a.txt");
        let mut w = builder.build(Cursor::new(Vec::new())).unwrap();
        while let Some(mut f) = w.next_file().unwrap() {
            f.write_all(b"MALWARETEST").unwrap();
        }
        let cab = w.finish().unwrap().into_inner();
        // The first CFDATA record of the one folder, from its CFFOLDER entry.
        let at = u64::from(u32::from_le_bytes(cab[36..40].try_into().unwrap()));
        let mut source = NoSeekTo {
            inner: Cursor::new(cab),
            at,
        };
        let mut budget = Budget::new(crate::Limits::default());
        let e = stream_cab(&mut source, &mut budget, &mut |_, _, _| None::<()>)
            .expect_err("the folder cannot be opened");
        assert!(e.is_corrupt(), "{}", e.reason);
        assert!(e.reason.starts_with("cab folder"), "{}", e.reason);
    }
}
