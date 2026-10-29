//! XAR archive extractor (macOS `.pkg` installers, `.xip` archives, some
//! Safari extensions).
//!
//! Layout: a 28-byte header, a zlib-compressed XML table of contents, then the
//! file heap. The TOC describes each file's data block as an offset/length into
//! the heap plus an encoding (commonly gzip/zlib). We parse the header, inflate
//! the TOC, and read each data block from the heap where it is (inflating
//! zlib-encoded blocks as they are read), emitting members for the engine to
//! recurse into. Neither the archive nor a member is held. The TOC XML is
//! scanned with a small targeted parser rather than a full XML dependency.

use crate::source::{ByteSource, Reader};
use crate::stream::{MemberMeta, Visit, emit_entry, emit_stream};
use crate::{Budget, Entry, LimitHit};
use flate2::read::ZlibDecoder;
use std::io::{BufReader, Read};

const MAGIC: &[u8] = b"xar!";

/// How much of what is read from the source for a member is buffered.
const BUFFER: usize = 64 * 1024;

/// The most the table of contents inflates to.
const TOC_CAP: u64 = 64 * 1024 * 1024;

fn be_u16(d: &[u8], p: usize) -> u64 {
    crate::bytes::at(d, p, 2)
        .map(|b| u64::from(u16::from_be_bytes([b[0], b[1]])))
        .unwrap_or(0)
}

fn be_u64(d: &[u8], p: usize) -> u64 {
    crate::bytes::at(d, p, 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// Walk a XAR archive. The table of contents is read from the front of the
/// source and each member from its place in the heap.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let head = src.window(0, 28);
    if head.len() < 28 || !head.starts_with(MAGIC) {
        return Err(LimitHit::corrupt("xar: bad magic".to_string()));
    }
    let len = src.len();
    let header_size = crate::bytes::to_usize(be_u16(&head, 4));
    let toc_comp = crate::bytes::to_usize(be_u64(&head, 8));
    let toc_uncomp = be_u64(&head, 16);
    let toc_start = header_size;
    let toc_end = toc_start.saturating_add(toc_comp);
    if toc_end > len {
        return Err(LimitHit::corrupt("xar: truncated TOC".to_string()));
    }
    let heap_start = toc_end;

    // Inflate the TOC (bounded by its declared uncompressed size, capped).
    let mut toc = Vec::new();
    ZlibDecoder::new(BufReader::with_capacity(
        BUFFER,
        Reader::range(src, toc_start, toc_end),
    ))
    .take(toc_uncomp.min(TOC_CAP))
    .read_to_end(&mut toc)
    .map_err(|e| LimitHit::new(format!("xar: TOC inflate: {e}")))?;
    let toc = String::from_utf8_lossy(&toc);

    for (name, blk) in iter_data_blocks(&toc) {
        let off = heap_start.saturating_add(blk.offset);
        let end = off.saturating_add(blk.length).min(len);
        // A zero-length block has nothing to scan; a block starting past EOF, or
        // one the bound above clamped short, is truncated — the declared bytes
        // are absent from this file rather than hidden in it, so what exists is
        // scanned and a clean result is honest. See docs/QUIRKS.md.
        if off >= len || blk.length == 0 {
            continue;
        }

        budget.count_entry()?;
        let raw = BufReader::with_capacity(BUFFER, Reader::range(src, off, end));
        let meta = MemberMeta {
            name: name.clone(),
            comp_size: end.saturating_sub(off) as u64,
            size: Some(blk.size as u64),
            ..MemberMeta::default()
        };
        let found = if blk.gzip {
            // Heap data is zlib-wrapped.
            match crate::inflate::zlib_reader(raw) {
                Ok(Some(mut z)) => emit_stream(&meta, &mut z, budget, &mut *visit)?,
                // Cut inside the zlib header: no byte of the stream is here.
                Err(_) if off.saturating_add(blk.length) > len => {
                    emit_stream(&meta, &mut std::io::empty(), budget, &mut *visit)?
                }
                _ => {
                    // The TOC names this member and its bytes are in the heap;
                    // the stream just would not inflate. Dropping it would leave
                    // a file the archive contains with no trace in the result.
                    emit_entry(
                        Entry::unsupported(
                            name,
                            blk.size as u64,
                            false,
                            "XAR member would not inflate",
                        ),
                        budget,
                        &mut *visit,
                    )?
                }
            }
        } else {
            let mut raw = raw;
            emit_stream(&meta, &mut raw, budget, &mut *visit)?
        };
        if let Some(r) = found {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

struct Block {
    offset: usize,
    length: usize,
    size: usize,
    gzip: bool,
}

/// Walk the TOC, pairing each `<data>` block with the nearest preceding
/// `<name>` (document order) for a human-readable label. Names are cosmetic for
/// scanning, so an approximate pairing is acceptable.
fn iter_data_blocks(toc: &str) -> Vec<(String, Block)> {
    let mut out = Vec::new();
    let mut search = 0usize;
    let mut last_name = String::from("xar-file");
    while let Some(rel) = toc[search..].find("<data>") {
        let data_open = search + rel;
        // Track the most recent <name> before this <data>.
        if let Some(n) = inner_text(&toc[..data_open], "name") {
            last_name = n;
        }
        let data_close = toc[data_open..]
            .find("</data>")
            .map(|r| data_open + r)
            .unwrap_or(toc.len());
        let block = &toc[data_open..data_close];
        let offset = inner_text(block, "offset")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let length = inner_text(block, "length")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let size = inner_text(block, "size")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(length);
        let gzip = block.contains("application/x-gzip") || block.contains("application/zlib");
        out.push((
            last_name.clone(),
            Block {
                offset,
                length,
                size,
                gzip,
            },
        ));
        // An unterminated `<data>` leaves `data_close == toc.len()`; clamp so the
        // next slice (`toc[search..]`) can never start past the end and panic.
        search = (data_close + 1).min(toc.len());
    }
    out
}

/// Extract the text of the LAST `<tag>...</tag>` in `hay`.
fn inner_text(hay: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = hay.rfind(&open)? + open.len();
    let end = hay[start..].find(&close)? + start;
    Some(hay[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Limits, Member, extract};
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// An archive of `members`: name, bytes, and whether they are stored
    /// zlib-compressed in the heap.
    fn archive(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut heap = Vec::new();
        let mut files = String::new();
        for (name, data, deflate) in members {
            let stored = if *deflate { zlib(data) } else { data.to_vec() };
            let style = if *deflate {
                "application/x-gzip"
            } else {
                "application/octet-stream"
            };
            files.push_str(&format!(
                "<file><name>{name}</name><data><offset>{}</offset><length>{}</length>\
                 <size>{}</size><encoding style=\"{style}\"/></data></file>",
                heap.len(),
                stored.len(),
                data.len()
            ));
            heap.extend_from_slice(&stored);
        }
        let toc_xml = format!("<xar><toc>{files}</toc></xar>");
        let toc_comp = zlib(toc_xml.as_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&28u16.to_be_bytes()); // header_size
        buf.extend_from_slice(&1u16.to_be_bytes()); // version
        buf.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
        buf.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // cksum alg
        buf.extend_from_slice(&toc_comp);
        buf.extend_from_slice(&heap);
        buf
    }

    #[test]
    fn extracts_one_gzip_member() {
        let payload = b"EICAR-ish payload bytes";
        let buf = archive(&[("evil.sh", payload, true)]);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xar, &buf, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil.sh");
        assert_eq!(entries[0].data, payload);
    }

    /// What `walk` gives of `buf` read from a source that is not in memory,
    /// under a buffer limit of `cap`: each member's name, bytes and whether
    /// it was read as it goes.
    fn off_a_source(buf: &[u8], cap: u64) -> Vec<(String, Vec<u8>, bool)> {
        let cache =
            crate::source::BlockCache::with_sizes(std::io::Cursor::new(buf.to_vec()), 64, 4 * 64)
                .unwrap();
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: cap,
            ..Limits::default()
        });
        let mut out = Vec::new();
        crate::walk(Format::Xar, &cache, &mut budget, &mut |meta, content, _| {
            let (data, streamed) = match content {
                None => (Vec::new(), false),
                Some(Member::Bytes(b)) => (b, false),
                Some(Member::Stream(r)) => {
                    let mut b = Vec::new();
                    r.read_to_end(&mut b).unwrap();
                    (b, true)
                }
            };
            assert!(meta.unsupported.is_none(), "{}", meta.name);
            out.push((meta.name.clone(), data, streamed));
            None::<()>
        })
        .unwrap();
        out
    }

    #[test]
    fn members_are_read_as_they_go_from_a_source_that_is_not_in_memory() {
        let big: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let buf = archive(&[
            ("deflated.bin", &big, true),
            ("stored.bin", &big, false),
            ("small.txt", b"small", true),
        ]);
        let got = off_a_source(&buf, 100);
        assert_eq!(
            got,
            [
                ("deflated.bin".to_string(), big.clone(), true),
                ("stored.bin".to_string(), big, true),
                ("small.txt".to_string(), b"small".to_vec(), true),
            ]
        );
    }

    #[test]
    fn a_member_cut_short_by_the_end_of_the_archive_comes_out_as_far_as_it_goes() {
        let big: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut buf = archive(&[("stored.bin", &big, false)]);
        buf.truncate(buf.len() - 1000);
        let got = off_a_source(&buf, 100);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, big[..big.len() - 1000]);
    }
}
