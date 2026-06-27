//! XAR archive extractor (macOS `.pkg` installers, `.xip` archives, some
//! Safari extensions).
//!
//! Layout: a 28-byte header, a zlib-compressed XML table of contents, then the
//! file heap. The TOC describes each file's data block as an offset/length into
//! the heap plus an encoding (commonly gzip/zlib). We parse the header, inflate
//! the TOC, and pull each data block out of the heap (inflating zlib-encoded
//! blocks), emitting members for the engine to recurse into. The TOC XML is
//! scanned with a small targeted parser rather than a full XML dependency.

use crate::*;
use flate2::read::ZlibDecoder;
use std::io::Read;

const MAGIC: &[u8] = b"xar!";

fn be_u16(d: &[u8], p: usize) -> u64 {
    u16::from_be_bytes([d[p], d[p + 1]]) as u64
}
fn be_u64(d: &[u8], p: usize) -> u64 {
    u64::from_be_bytes([
        d[p], d[p + 1], d[p + 2], d[p + 3], d[p + 4], d[p + 5], d[p + 6], d[p + 7],
    ])
}

pub(crate) fn extract_xar<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if data.len() < 28 || !data.starts_with(MAGIC) {
        return Err(LimitHit::new("xar: bad magic".to_string()));
    }
    let header_size = be_u16(data, 4) as usize;
    let toc_comp = be_u64(data, 8) as usize;
    let toc_uncomp = be_u64(data, 16) as usize;
    let toc_start = header_size;
    let toc_end = toc_start.saturating_add(toc_comp);
    if toc_end > data.len() {
        return Err(LimitHit::new("xar: truncated TOC".to_string()));
    }
    let heap_start = toc_end;

    // Inflate the TOC (bounded by its declared uncompressed size, capped).
    let toc_cap = toc_uncomp.min(64 * 1024 * 1024);
    let mut toc = Vec::new();
    ZlibDecoder::new(&data[toc_start..toc_end])
        .take(toc_cap as u64)
        .read_to_end(&mut toc)
        .map_err(|e| LimitHit::new(format!("xar: TOC inflate: {e}")))?;
    let toc = String::from_utf8_lossy(&toc);

    for (name, blk) in iter_data_blocks(&toc) {
        let off = heap_start.saturating_add(blk.offset);
        let end = off.saturating_add(blk.length).min(data.len());
        if off >= data.len() || blk.length == 0 {
            continue;
        }
        let raw = &data[off..end];

        budget.count_entry()?;
        let cap = budget.reserve()?;
        let member = if blk.gzip {
            // Heap data is zlib-wrapped; inflate bounded by the declared size.
            let want = blk.size.min(cap as usize);
            let mut out = Vec::new();
            if ZlibDecoder::new(raw)
                .take(want as u64 + 1)
                .read_to_end(&mut out)
                .is_err()
            {
                continue;
            }
            if out.len() as u64 > cap {
                return Err(LimitHit::new(format!("xar member '{name}' exceeds budget")));
            }
            out
        } else {
            if raw.len() as u64 > cap {
                return Err(LimitHit::new(format!("xar member '{name}' exceeds budget")));
            }
            raw.to_vec()
        };
        budget.commit(member.len() as u64);
        if let Some(r) = visit(Entry::new(name, member), budget) {
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
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn extracts_one_gzip_member() {
        let payload = b"EICAR-ish payload bytes";
        let heap = zlib(payload);
        let toc_xml = format!(
            "<xar><toc><file><name>evil.sh</name><data><offset>0</offset>\
             <length>{}</length><size>{}</size>\
             <encoding style=\"application/x-gzip\"/></data></file></toc></xar>",
            heap.len(),
            payload.len()
        );
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

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xar, &buf, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "evil.sh");
        assert_eq!(entries[0].data, payload);
    }
}
